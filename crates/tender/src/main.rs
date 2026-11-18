use std::{io, process::ExitCode};

#[cfg(unix)]
use tender::cli;
use tracing_subscriber::fmt;

#[tokio::main]
async fn main() -> ExitCode {
    fmt().with_writer(io::stderr).init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tender: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(unix)]
async fn run() -> Result<(), String> {
    cli::main().await
}

#[cfg(not(unix))]
async fn run() -> Result<(), String> {
    Err("tender runs on Unix only".into())
}
