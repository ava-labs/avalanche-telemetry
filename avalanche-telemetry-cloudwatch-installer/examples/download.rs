use std::io;

use avalanche_telemetry_cloudwatch_installer::github;

/// cargo run --example download
#[tokio::main]
async fn main() -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let bin_path = random_manager::tmp_path(10, None)?;
    github::download_latest(None, None, &bin_path)
        .await
        .unwrap();
    log::info!("downloaded {bin_path}");

    Ok(())
}
