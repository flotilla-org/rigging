//! Reading a command's stdout line by line as it arrives.
//!
//! [`CommandRunner::stream_lines`](crate::CommandRunner::stream_lines) is for
//! commands that may never end on their own, such as `docker events`: the
//! caller acts on each line as it is written, rather than waiting for the
//! command to exit. Dropping the stream stops the command.

use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};

/// The longest line a stream returns, counting its line ending. A longer line
/// is an error, so a command writing without line endings cannot grow the
/// buffer without bound.
pub const MAX_LINE_BYTES: usize = 1 << 20;
/// How much of stderr a failed stream reports: its first bytes.
pub const STDERR_REPORT_BYTES: u64 = 64 << 10;

/// A running command whose stdout is read one line at a time.
///
/// Dropping it stops the command, and any processes it started, if it is
/// still running.
#[async_trait]
pub trait CommandLines: Send {
    /// The next line of stdout, without its line ending. Bytes that are not
    /// UTF-8 are replaced. Once stdout closes, the stream waits for the
    /// command: `Ok(None)` if it succeeded, otherwise `Err` with its stderr.
    /// An error ends the stream; later calls return `Ok(None)`.
    async fn next_line(&mut self) -> Result<Option<String>, String>;
}

/// A local child's stdout, read line by line; stderr is drained alongside.
pub(crate) struct ChildLines {
    child: tokio::process::Child,
    stdout: BufReader<tokio::process::ChildStdout>,
    stderr: tokio::task::JoinHandle<Vec<u8>>,
    // A partial line survives a cancelled `next_line`.
    buffer: Vec<u8>,
    ended: bool,
    #[cfg(unix)]
    group: crate::ProcessGroupGuard,
}

impl ChildLines {
    /// Takes over `command`, configured by the runner, and starts it.
    pub(crate) fn spawn(mut command: tokio::process::Command) -> Result<Self, String> {
        let mut child = command
            .kill_on_drop(true)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|error| error.to_string())?;
        #[cfg(unix)]
        let group = crate::ProcessGroupGuard::for_child(&child)?;
        // Spawn above requested both pipes; neither has been taken.
        let stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        let stderr = tokio::spawn(stderr_report(child.stderr.take().expect("piped stderr")));
        Ok(Self {
            child,
            stdout,
            stderr,
            buffer: Vec::new(),
            ended: false,
            #[cfg(unix)]
            group,
        })
    }

    async fn read_line(&mut self) -> Result<Option<String>, String> {
        let room = (MAX_LINE_BYTES - self.buffer.len()) as u64;
        let read = (&mut self.stdout).take(room).read_until(b'\n', &mut self.buffer).await.map_err(|error| error.to_string())?;
        if self.buffer.last() != Some(&b'\n') && self.buffer.len() == MAX_LINE_BYTES {
            return Err(format!("stdout line longer than {MAX_LINE_BYTES} bytes"));
        }
        if read > 0 || !self.buffer.is_empty() {
            return Ok(Some(line_text(std::mem::take(&mut self.buffer))));
        }
        let status = self.child.wait().await.map_err(|error| error.to_string())?;
        // Reaped: the group ID may be reused, so it must not be signalled.
        #[cfg(unix)]
        {
            self.group.0 = 0;
        }
        if status.success() {
            return Ok(None);
        }
        // A process the command started may still hold stderr open.
        let stderr =
            tokio::time::timeout(crate::OUTPUT_DRAIN_TIMEOUT, &mut self.stderr).await.ok().and_then(Result::ok).unwrap_or_default();
        let stderr = String::from_utf8_lossy(&stderr);
        Err(if stderr.trim().is_empty() { format!("command exited with {status}") } else { stderr.into_owned() })
    }
}

/// Keeps the first [`STDERR_REPORT_BYTES`] of `pipe` and discards the rest, so
/// a chatty command never blocks on a full stderr pipe.
async fn stderr_report(mut pipe: impl AsyncRead + Unpin) -> Vec<u8> {
    let mut report = Vec::new();
    let _ = (&mut pipe).take(STDERR_REPORT_BYTES).read_to_end(&mut report).await;
    let _ = tokio::io::copy(&mut pipe, &mut tokio::io::sink()).await;
    report
}

#[async_trait]
impl CommandLines for ChildLines {
    async fn next_line(&mut self) -> Result<Option<String>, String> {
        if self.ended {
            return Ok(None);
        }
        let line = self.read_line().await;
        self.ended = !matches!(line, Ok(Some(_)));
        line
    }
}

impl Drop for ChildLines {
    fn drop(&mut self) {
        self.stderr.abort();
    }
}

/// A line's text without its `\n` or `\r\n` ending.
fn line_text(mut bytes: Vec<u8>) -> String {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    String::from_utf8(bytes).unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned())
}

#[cfg(test)]
mod tests {
    use std::{path::Path, time::Duration};

    use super::*;
    use crate::{ChannelLabel, CommandRunner, ProcessCommandRunner};

    async fn lines(script: &str) -> Box<dyn CommandLines> {
        ProcessCommandRunner.stream_lines("sh", &["-c", script], Path::new("/"), &ChannelLabel::Default).await.expect("spawn")
    }

    // A line is returned as soon as it is written, while the command still runs.
    #[tokio::test]
    async fn each_line_arrives_while_the_command_runs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let gate = dir.path().join("gate");
        let script = format!("echo first; while [ ! -e '{}' ]; do sleep 0.01; done; echo second", gate.display());
        let mut stream = lines(&script).await;
        let first = tokio::time::timeout(Duration::from_secs(5), stream.next_line()).await.expect("first line before exit");
        assert_eq!(first.expect("read"), Some("first".into()));
        std::fs::write(&gate, "").expect("open the gate");
        assert_eq!(stream.next_line().await.expect("read"), Some("second".into()));
        assert_eq!(stream.next_line().await.expect("success"), None);
    }

    // Line endings are dropped, a final unterminated line is kept, and a failed command ends the
    // stream with its stderr.
    #[tokio::test]
    async fn a_failed_command_ends_with_its_stderr() {
        let mut stream = lines("printf 'a\\r\\nb\\n\\nlast'; echo oops >&2; exit 3").await;
        for expected in ["a", "b", "", "last"] {
            assert_eq!(stream.next_line().await.expect("read"), Some(expected.into()));
        }
        assert_eq!(stream.next_line().await, Err("oops\n".into()));
        assert_eq!(stream.next_line().await, Ok(None));
    }

    // A line over the bound is an error that ends the stream, rather than an unbounded buffer.
    #[tokio::test]
    async fn an_over_long_line_ends_the_stream() {
        let mut stream = lines(&format!("head -c {MAX_LINE_BYTES} /dev/zero | tr '\\0' x; echo; echo next")).await;
        assert!(stream.next_line().await.expect_err("too long").contains("longer than"));
        assert_eq!(stream.next_line().await, Ok(None));
    }

    // stderr is drained as the command runs, so a command writing more than a pipe holds to stderr
    // is not blocked; only its start is reported.
    #[tokio::test]
    async fn heavy_stderr_never_blocks_stdout() {
        let mut stream = lines("head -c 1000000 /dev/zero >&2; echo done; exit 1").await;
        let line = tokio::time::timeout(Duration::from_secs(10), stream.next_line()).await.expect("not blocked");
        assert_eq!(line.expect("read"), Some("done".into()));
        assert_eq!(stream.next_line().await.expect_err("failed").len() as u64, STDERR_REPORT_BYTES);
    }

    // Dropping the stream stops a command that would never end, and the processes it started.
    #[cfg(unix)]
    #[tokio::test]
    async fn dropping_the_stream_stops_the_command() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pid_path = dir.path().join("child.pid");
        let script = format!("sleep 30 & echo $! > '{}'; echo started; wait", pid_path.display());
        let mut stream = lines(&script).await;
        assert_eq!(stream.next_line().await.expect("read"), Some("started".into()));
        let pid: i32 = std::fs::read_to_string(&pid_path).expect("pid").trim().parse().expect("numeric pid");
        drop(stream);
        tokio::time::timeout(Duration::from_secs(5), async {
            while unsafe { libc::kill(pid, 0) } == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the command's child is stopped");
    }
}
