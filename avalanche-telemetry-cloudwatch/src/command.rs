use std::{
    env,
    io::{self, Error, ErrorKind},
};

use aws_manager::{self, cloudwatch, ec2};
use clap::{crate_version, Arg, Command};
use tokio::time::{sleep, Duration};

pub const NAME: &str = "avalanche-telemetry-cloudwatch";

pub fn new() -> Command<'static> {
    Command::new(NAME)
        .version(crate_version!())
        .about("Fetches the Avalanche node metrics and publishes to AWS CloudWatch")
        .long_about(
            "


Requires IAM instance role of: cloudwatch:PutMetricData.

e.g.,

$ avalanche-telemetry-cloudwatch \
--log-level=info \
--initial-wait-seconds=10 \
--fetch-interval-seconds=60 \
--endpoint=http://localhost:9650/ext/metrics


",
        )
        .arg(
            Arg::new("LOG_LEVEL")
                .long("log-level")
                .short('l')
                .help("Sets the log level")
                .required(false)
                .takes_value(true)
                .possible_value("debug")
                .possible_value("info")
                .allow_invalid_utf8(false)
                .default_value("info"),
        )
        .arg(
            Arg::new("INITIAL_WAIT_SECONDS")
                .long("initial-wait-seconds")
                .help("Sets the initial wait duration in seconds")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false)
                .default_value("0"),
        )
        .arg(
            Arg::new("FETCH_INTERVAL_SECONDS")
                .long("fetch-interval-seconds")
                .help("Sets the fetch interval duration in seconds")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false)
                .default_value("60"),
        )
        .arg(
            Arg::new("ENDPOINT")
                .long("endpoint")
                .help("Sets the metrics endpoint")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false)
                .default_value("http://localhost:9650/ext/metrics"),
        )
}

/// Defines flag options.
pub struct Flags {
    pub log_level: String,
    pub initial_wait_seconds: u32,
    pub fetch_interval_seconds: u32,

    pub endpoint: String,
}

pub async fn execute(opts: Flags) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opts.log_level),
    );
    log::info!("starting 'avalanche-telemetry-cloudwatch'");

    let shared_config = aws_manager::load_config(None).await?;
    let cw_manager = cloudwatch::Manager::new(&shared_config);

    let az = ec2::metadata::fetch_availability_zone()
        .await
        .map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed fetch_availability_zone '{}'", e),
            )
        })?;
    let ec2_instance_id = ec2::metadata::fetch_instance_id().await.map_err(|e| {
        Error::new(
            ErrorKind::Other,
            format!("failed fetch_instance_id '{}'", e),
        )
    })?;

    if opts.initial_wait_seconds > 0 {
        log::info!("waiting for initial seconds {}", opts.initial_wait_seconds);
        sleep(Duration::from_secs(opts.initial_wait_seconds as u64)).await;
    } else {
        log::info!("skipping initial sleep...");
    }

    log::info!("successfully mounted and provisioned the volume!");
    Ok(())
}
