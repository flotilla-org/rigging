//! Child processes held as the async runtime's own work.
//!
//! Tokio's paused test time jumps to the next timer whenever the runtime has nothing to run. A
//! child process is work the runtime cannot see: while the runtime waits for it to exit, a paused
//! clock would jump past every deadline set around it. On a current-thread runtime the guard
//! below is a blocking-pool job that waits for the guard's end, and tokio counts a blocking-pool
//! job as running work, so no timer comes due while a child the guard covers runs. A
//! multi-thread runtime never pauses its time, so there the guard holds nothing.

/// Holds the current runtime busy while the returned guard lives: hold one from a child's spawn
/// until its result is back. See the [module docs](self).
pub fn busy() -> Busy {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else { return Busy(None) };
    if runtime.runtime_flavor() != tokio::runtime::RuntimeFlavor::CurrentThread {
        return Busy(None);
    }
    let (held, ended) = std::sync::mpsc::channel::<()>();
    drop(runtime.spawn_blocking(move || {
        // Returns once the guard drops its sender.
        let _ = ended.recv();
    }));
    Busy(Some(held))
}

/// Holds the runtime busy while it lives: see [`busy`].
#[must_use = "the runtime is busy only while the guard lives"]
#[derive(Debug)]
pub struct Busy(#[allow(dead_code)] Option<std::sync::mpsc::Sender<()>>);

// The child is a Unix `sleep`; the process scenarios run on Linux.
#[cfg(all(test, unix))]
mod tests {
    use crate::{ChannelLabel, CommandRunner, ProcessCommandRunner};
    use std::{future::Future, path::Path, time::Duration};

    /// Runs `child` beside a 1 ms timer on the paused clock: whether the timer fired only once
    /// the child was done, and how far virtual time moved.
    async fn timer_beside<T>(child: impl Future<Output = T>) -> (bool, Duration) {
        let started = tokio::time::Instant::now();
        let timer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1)).await;
            std::time::Instant::now()
        });
        child.await;
        let done = std::time::Instant::now();
        let fired = timer.await.expect("timer");
        (fired >= done, started.elapsed())
    }

    // Behaviour: a paused clock does not move while the runner's child runs: a timer due during
    // the run fires only once the run is done, at its own virtual time, for each way of running.
    #[tokio::test(start_paused = true)]
    async fn a_timer_due_while_a_child_runs_fires_only_once_it_is_done() {
        let (runner, cwd, label) = (ProcessCommandRunner, Path::new("/"), ChannelLabel::Default);
        let args = ["0.3"];
        let runs = [
            timer_beside(async { runner.run("sleep", &args, cwd, &label).await.expect("run") }).await,
            timer_beside(async { runner.run_output("sleep", &args, cwd, &label).await.expect("output") }).await,
            timer_beside(async {
                runner.run_with_timeout("sleep", &args, cwd, &label, Duration::from_secs(60)).await.expect("run with timeout")
            })
            .await,
            timer_beside(async {
                runner.run_output_with_grace("sleep", &args, cwd, &label, Duration::from_secs(5)).await.expect("output with grace")
            })
            .await,
        ];
        assert_eq!(runs, [(true, Duration::from_millis(1)); 4], "each timer fired after its child, at +1 ms virtual");
    }
}
