#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tender: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(unix)]
async fn run() -> Result<(), String> {
    tender::cli::main().await
}

#[cfg(not(unix))]
async fn run() -> Result<(), String> {
    Err("tender runs on Unix only".into())
}
