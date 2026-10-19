//! Generic probes inside the runner execution environment.
use crate::CommandRunner;
use std::path::{Path, PathBuf};
use tracing::warn;

pub type VersionParser = fn(&str) -> Option<String>;

/// Probe a command version without resolving it on the caller host.
pub async fn command_version(
    runner: &dyn CommandRunner,
    command: &str,
    args: &[&str],
    parse: VersionParser,
) -> Result<Option<String>, String> {
    let output = crate::run!(runner, command, args, Path::new("/"))?;
    Ok(parse(&output))
}

/// Resolve a command that already passed its probe to the absolute executable
/// path inside the runner's environment.
///
/// This is deliberately a second runner call, not a `which`-style lookup on
/// the daemon host: the runner may be remote or provisioned, so the daemon's
/// own `PATH` can name a different binary or none.
pub async fn resolve_binary_path(runner: &dyn CommandRunner, command: &str) -> Option<PathBuf> {
    resolve_binary_path_with_marker(runner, command, "rigging-binary-discovery").await
}

/// Resolve in the runner environment, supplying the shell's `$0` marker.
/// Consumers can retain their historical argv marker so recorded fixtures replay
/// unchanged. The marker is a separate argument, never shell-interpolated.
pub async fn resolve_binary_path_with_marker(runner: &dyn CommandRunner, command: &str, marker: &str) -> Option<PathBuf> {
    // Resolve inside the runner's environment: provisioned and remote runners
    // intentionally do not share the daemon process's PATH.
    let output = match runner.run("sh", &["-c", "command -v \"$1\"", marker, command], Path::new("/"), &crate::ChannelLabel::Default).await
    {
        Ok(output) => output,
        Err(error) => {
            warn!(binary = command, %error, "binary path resolution failed after successful version probe");
            return None;
        }
    };
    let path = PathBuf::from(output.trim());
    if path.is_absolute() {
        Some(path)
    } else {
        warn!(binary = command, resolved_path = %path.display(), "binary path resolution returned a relative path after successful version probe");
        None
    }
}

/// The first token of digits containing at least one dot, such as `2.43.0`.
pub fn parse_first_dotted_version(output: &str) -> Option<String> {
    let mut start = None;
    let mut dot_count = 0;
    let mut saw_digit = false;

    for (idx, ch) in output.char_indices() {
        let Some(begin) = start else {
            if ch.is_ascii_digit() {
                start = Some(idx);
                saw_digit = true;
            }
            continue;
        };

        if ch.is_ascii_digit() {
            saw_digit = true;
            continue;
        }

        if ch == '.' {
            dot_count += 1;
            saw_digit = false;
            continue;
        }

        if dot_count > 0 && saw_digit {
            return Some(output[begin..idx].to_string());
        }

        start = if ch.is_ascii_digit() { Some(idx) } else { None };
        dot_count = 0;
        saw_digit = ch.is_ascii_digit();
    }

    if let Some(start) = start
        && dot_count > 0
        && saw_digit
    {
        return Some(output[start..].trim().to_string());
    }

    None
}
