use clap::{Parser, Subcommand};

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
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();
    let result = match Cli::parse().command {
        Command::Serve => serve().await,
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tender: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(unix)]
async fn serve() -> Result<(), String> {
    let paths = tender::daemon::Paths::from_env(&rigging_process::ProcessEnvVars)?;
    tender::daemon::serve(paths).await.map_err(|error| error.to_string())
}

#[cfg(not(unix))]
async fn serve() -> Result<(), String> {
    Err("the Tender daemon runs on Unix only".into())
}
