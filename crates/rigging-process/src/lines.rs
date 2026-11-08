//! Reading a command's stdout line by line as it arrives.
//!
//! [`CommandRunner::stream_lines`](crate::CommandRunner::stream_lines) is for
//! commands that may never end on their own, such as `docker events`: the
//! caller acts on each line as it is written, rather than waiting for the
//! command to exit. Dropping the stream stops the command.

use std::path::Path;

use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};

use crate::CommandOutput;

/// The longest line a stream returns. A longer line is an error, so a command
/// that writes without line endings cannot grow the buffer without bound.
pub const MAX_LINE_BYTES: usize = 1 << 20;
/// How much of stderr a stream keeps: its last bytes, for the exit report.
pub const STDERR_TAIL_BYTES: usize = 64 << 10;

/// A running command whose stdout is read one line at a time.
///
/// Dropping it stops the command, and any processes it started, if it is
/// still running.
#[async_trait]
pub trait CommandLines: Send {
    /// The next complete line of stdout, without its line ending; `Ok(None)`
    /// once stdout has closed. A final line with no line ending is returned
    /// when stdout closes. Bytes that are not UTF-8 are replaced.
    async fn next_line(&mut self) -> Result<Option<String>, String>;

    /// Waits for the command to exit, once [`Self::next_line`] has returned
    /// `Ok(None)`. The output's `stdout` is empty: the lines were the stdout.
    /// Its `stderr` is the last [`STDERR_TAIL_BYTES`] of stderr.
    async fn finish(&mut self) -> Result<CommandOutput, String>;
}

/// A local child's stdout, read line by line; stderr is drained alongside.
pub(crate) struct ChildLines {
    child: tokio::process::Child,
    stdout: BufReader<tokio::process::ChildStdout>,
    stderr: Option<tokio::task::JoinHandle<std::io::Result<Vec<u8>>>>,
    buffer: Vec<u8>,
    closed: bool,
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
        let stderr = child.stderr.take().expect("piped stderr");
        Ok(Self {
            child,
            stdout,
            stderr: Some(tokio::spawn(stderr_tail(stderr))),
            buffer: Vec::new(),
            closed: false,
            #[cfg(unix)]
            group,
        })
    }
}

/// Reads `pipe` to its end, keeping only its last [`STDERR_TAIL_BYTES`], so a
/// chatty command never blocks on a full stderr pipe.
async fn stderr_tail(mut pipe: impl AsyncRead + Unpin) -> std::io::Result<Vec<u8>> {
    let mut tail = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let read = pipe.read(&mut chunk).await?;
        if read == 0 {
            return Ok(tail);
        }
        tail.extend_from_slice(&chunk[..read]);
        if tail.len() > STDERR_TAIL_BYTES {
            tail.drain(..tail.len() - STDERR_TAIL_BYTES);
        }
    }
}

#[async_trait]
impl CommandLines for ChildLines {
    async fn next_line(&mut self) -> Result<Option<String>, String> {
        if self.closed {
            return Ok(None);
        }
        loop {
            let available = self.stdout.fill_buf().await.map_err(|error| error.to_string())?;
            if available.is_empty() {
                self.closed = true;
                if self.buffer.is_empty() {
                    return Ok(None);
                }
                return Ok(Some(line_text(std::mem::take(&mut self.buffer))));
            }
            let (used, complete) = match available.iter().position(|byte| *byte == b'\n') {
                Some(end) => (end + 1, true),
                None => (available.len(), false),
            };
            self.buffer.extend_from_slice(&available[..used]);
            self.stdout.consume(used);
            if self.buffer.len() > MAX_LINE_BYTES + 2 {
                return Err(format!("stdout line longer than {MAX_LINE_BYTES} bytes"));
            }
            if complete {
                return Ok(Some(line_text(std::mem::take(&mut self.buffer))));
            }
        }
    }

    async fn finish(&mut self) -> Result<CommandOutput, String> {
        let status = self.child.wait().await.map_err(|error| error.to_string())?;
        // Reaped: the group ID may be reused, so it must not be signalled.
        #[cfg(unix)]
        {
            self.group.0 = 0;
        }
        let stderr = match self.stderr.take() {
            Some(task) => match tokio::time::timeout(crate::OUTPUT_DRAIN_TIMEOUT, task).await {
                Ok(joined) => joined.map_err(|error| error.to_string())?.map_err(|error| error.to_string())?,
                // A process the command started still holds stderr open.
                Err(_) => Vec::new(),
            },
            None => Vec::new(),
        };
        Ok(CommandOutput { stdout: String::new(), stderr: String::from_utf8_lossy(&stderr).into_owned(), exit_code: status.code() })
    }
}

impl Drop for ChildLines {
    fn drop(&mut self) {
        if let Some(task) = self.stderr.take() {
            task.abort();
        }
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

/// Lines given up front, then an end: a stand-in for tests and replays.
pub struct ScriptedLines {
    lines: std::collections::VecDeque<String>,
    end: Option<CommandOutput>,
}

impl ScriptedLines {
    /// Returns `lines`, then ends with `end`. With no `end`, the command never
    /// ends on its own: after the lines, [`CommandLines::next_line`] waits
    /// until the stream is dropped, as a live never-ending command would.
    pub fn new(lines: impl IntoIterator<Item = String>, end: Option<CommandOutput>) -> Self {
        Self { lines: lines.into_iter().collect(), end }
    }
}

#[async_trait]
impl CommandLines for ScriptedLines {
    async fn next_line(&mut self) -> Result<Option<String>, String> {
        if let Some(line) = self.lines.pop_front() {
            return Ok(Some(line));
        }
        match self.end {
            Some(_) => Ok(None),
            None => std::future::pending().await,
        }
    }

    async fn finish(&mut self) -> Result<CommandOutput, String> {
        match &self.end {
            Some(end) => Ok(end.clone()),
            None => std::future::pending().await,
        }
    }
}

/// Spawns `cmd` for [`crate::ProcessRunner`]'s line stream.
pub(crate) async fn spawn_lines<G: crate::CommandGuard>(
    runner: &crate::ProcessRunner<G>,
    cmd: &str,
    args: &[&str],
    cwd: &Path,
) -> Result<Box<dyn CommandLines>, String> {
    let command = runner.checked_command(cmd, args, cwd).await?;
    Ok(Box::new(ChildLines::spawn(command)?))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

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
        assert_eq!(stream.next_line().await.expect("read"), None);
        assert_eq!(stream.finish().await.expect("finish").exit_code, Some(0));
    }

    // Line endings are dropped, a final unterminated line is kept, and the end reports the exit
    // code and stderr.
    #[tokio::test]
    async fn the_end_reports_exit_code_and_stderr() {
        let mut stream = lines("printf 'a\\r\\nb\\n\\nlast'; echo oops >&2; exit 3").await;
        let mut read = Vec::new();
        while let Some(line) = stream.next_line().await.expect("read") {
            read.push(line);
        }
        assert_eq!(read, ["a", "b", "", "last"]);
        assert_eq!(stream.next_line().await.expect("after the end"), None);
        let end = stream.finish().await.expect("finish");
        assert_eq!((end.stdout.as_str(), end.stderr.as_str(), end.exit_code), ("", "oops\n", Some(3)));
    }

    // A line over the bound is an error rather than an unbounded buffer.
    #[tokio::test]
    async fn an_over_long_line_is_an_error() {
        let mut stream = lines(&format!("head -c {} /dev/zero | tr '\\0' x; echo", MAX_LINE_BYTES + 3)).await;
        assert!(stream.next_line().await.expect_err("too long").contains("longer than"));
    }

    // stderr is drained as the command runs, so a command writing more than a pipe holds to stderr
    // is not blocked; only its tail is kept.
    #[tokio::test]
    async fn heavy_stderr_never_blocks_stdout() {
        let mut stream = lines("head -c 1000000 /dev/zero >&2; echo done").await;
        let line = tokio::time::timeout(Duration::from_secs(10), stream.next_line()).await.expect("not blocked");
        assert_eq!(line.expect("read"), Some("done".into()));
        assert_eq!(stream.next_line().await.expect("read"), None);
        assert_eq!(stream.finish().await.expect("finish").stderr.len(), STDERR_TAIL_BYTES);
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

    // A runner without line streams says so.
    #[tokio::test]
    async fn a_runner_without_line_streams_refuses() {
        struct Plain;
        #[async_trait]
        impl CommandRunner for Plain {
            async fn run(&self, _: &str, _: &[&str], _: &Path, _: &ChannelLabel) -> Result<String, String> {
                unreachable!()
            }
            async fn run_output(&self, _: &str, _: &[&str], _: &Path, _: &ChannelLabel) -> Result<CommandOutput, String> {
                unreachable!()
            }
            async fn exists(&self, _: &str, _: &[&str]) -> bool {
                unreachable!()
            }
        }
        let refused = Plain.stream_lines("docker", &["events"], Path::new("/"), &ChannelLabel::Default).await;
        assert!(refused.err().expect("refused").contains("does not support line streams"));
    }

    // Scripted lines end with their end, or, with none, wait as a never-ending command would.
    #[tokio::test]
    async fn scripted_lines_end_or_wait() {
        let end = CommandOutput { stdout: String::new(), stderr: "gone".into(), exit_code: Some(1) };
        let mut ended = ScriptedLines::new(["a".to_string()], Some(end.clone()));
        assert_eq!(ended.next_line().await.expect("read"), Some("a".into()));
        assert_eq!(ended.next_line().await.expect("read"), None);
        assert_eq!(ended.finish().await.expect("finish"), end);
        let mut endless = ScriptedLines::new(["a".to_string()], None);
        assert_eq!(endless.next_line().await.expect("read"), Some("a".into()));
        assert!(tokio::time::timeout(Duration::from_millis(50), endless.next_line()).await.is_err(), "waits for more");
    }
}
