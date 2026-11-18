use std::{io, process::ExitCode};

use clap::{Parser, Subcommand};
#[cfg(unix)]
use rigging_process::ProcessEnvVars;
#[cfg(unix)]
use tender::daemon::{self, Paths};
use tracing_subscriber::fmt;

#[derive(Parser)]
#[command(name = "tender", about = "Publish this account's local endpoints and keep Bindings to others' publications")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run this account's daemon until SIGINT or SIGTERM.
    Serve,
}

#[tokio::main]
async fn main() -> ExitCode {
    fmt().with_writer(io::stderr).init();
    let result = match Cli::parse().command {
        Command::Serve => serve().await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tender: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(unix)]
async fn serve() -> Result<(), String> {
    let paths = Paths::from_env(&ProcessEnvVars)?;
    daemon::serve(paths).await.map_err(|error| error.to_string())
}

#[cfg(not(unix))]
async fn serve() -> Result<(), String> {
    Err("the Tender daemon runs on Unix only".into())
}
