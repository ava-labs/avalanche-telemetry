use std::{
    env,
    io::{self, Error, ErrorKind},
};

use aws_manager::{self, cloudwatch, ec2};
use aws_sdk_cloudwatch::{
    primitives::DateTime as SmithyDateTime,
    types::{MetricDatum, StandardUnit},
};
use chrono::Utc;
use clap::{crate_version, value_parser, Arg, Command};
use reqwest::ClientBuilder;
use tokio::time::{sleep, Duration};

pub const NAME: &str = "avalanche-telemetry-cloudwatch";

pub fn new() -> Command {
    Command::new(NAME)
        .version(crate_version!())
        .about("Fetches the Avalanche node metrics and publishes to AWS CloudWatch")
        .long_about(
            "

Scrapes the Prometheus metrics from the Avalanche node based on the rules (e.g., regex).
And publishes the data to AWS CloudWatch.

Requires IAM instance role of: cloudwatch:PutMetricData.

e.g.,

$ avalanche-telemetry-cloudwatch \
--log-level=info \
--initial-wait-seconds=10 \
--fetch-interval-seconds=300 \
--rules-file-path=/data/avalanche-telemetry-cloudwatch.rules.yaml \
--namespace=mine \
--rpc-endpoint=http://localhost:9650



",
        )
        .arg(
            Arg::new("LOG_LEVEL")
                .long("log-level")
                .short('l')
                .help("Sets the log level")
                .required(false)
                .num_args(1)
                .value_parser(["debug", "info"])
                .default_value("info"),
        )
        .arg(
            Arg::new("INITIAL_WAIT_SECONDS")
                .long("initial-wait-seconds")
                .help("Sets the initial wait duration in seconds")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u32))
                .default_value("5"),
        )
        .arg(
            Arg::new("FETCH_INTERVAL_SECONDS")
                .long("fetch-interval-seconds")
                .help("Sets the fetch interval duration in seconds")
                .required(false)
                .num_args(1)
                .value_parser(value_parser!(u32))
                .default_value("3600"), // 60-minute
        )
        .arg(
            Arg::new("RULES_FILE_PATH")
                .long("rules-file-path")
                .help("Sets the file path for rules")
                .required(false)
                .num_args(1)
                .default_value("/data/avalanche-telemetry-cloudwatch.rules.yaml"),
        )
        .arg(
            Arg::new("NAMESPACE")
                .long("namespace")
                .help("Sets the namespace")
                .required(false)
                .num_args(1)
                .default_value("avalanche-telemetry-cloudwatch"),
        )
        .arg(
            Arg::new("RPC_ENDPOINT")
                .long("rpc-endpoint")
                .help("Sets the endpoint")
                .required(false)
                .num_args(1)
                .default_value("http://localhost:9650"),
        )
}

/// Defines flag options.
pub struct Flags {
    pub log_level: String,

    pub initial_wait_seconds: u32,
    pub fetch_interval_seconds: u32,

    pub rules_file_path: String,
    pub namespace: String,

    pub rpc_endpoint: String,
}

/// 20-minute
pub const DEFAULT_INTERVAL_SECONDS: u64 = 3600;

pub async fn execute(opts: Flags) -> io::Result<()> {
    println!("{} version: {}", NAME, crate_version!());

    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opts.log_level),
    );
    log::info!(
        "starting 'avalanche-telemetry-cloudwatch' for rules file '{}', namespace '{}', and RPC endpoint '{}'",
        opts.rules_file_path,
        opts.namespace,
        opts.rpc_endpoint
    );

    let az = ec2::metadata::fetch_availability_zone()
        .await
        .map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed fetch_availability_zone '{}'", e),
            )
        })?;
    log::info!("availability zone {}", az);

    let ec2_instance_id = ec2::metadata::fetch_instance_id().await.map_err(|e| {
        Error::new(
            ErrorKind::Other,
            format!("failed fetch_instance_id '{}'", e),
        )
    })?;
    log::info!("local EC2 instance Id {}", ec2_instance_id);

    if opts.initial_wait_seconds > 0 {
        log::info!("waiting for initial seconds {}", opts.initial_wait_seconds);
        sleep(Duration::from_secs(opts.initial_wait_seconds as u64)).await;
    } else {
        log::info!("skipping initial sleep...");
    }

    let fetch_interval = if opts.fetch_interval_seconds >= 60 {
        Duration::from_secs(opts.fetch_interval_seconds as u64)
    } else {
        log::info!(
            "fetch interval seconds {} too small (< minimum 60 seconds) -- defaults to {} to prevent DDOS/CloudWatch bill blowups",
            opts.fetch_interval_seconds,
            DEFAULT_INTERVAL_SECONDS
        );
        Duration::from_secs(DEFAULT_INTERVAL_SECONDS)
    };
    log::info!("fetch interval {:?}", fetch_interval);

    let shared_config = aws_manager::load_config(None, Some(Duration::from_secs(30))).await;
    let cw_manager = cloudwatch::Manager::new(&shared_config);
    loop {
        log::info!(
            "will fetch metrics at '{}' after {:?}",
            opts.rpc_endpoint,
            fetch_interval,
        );
        sleep(fetch_interval).await;

        let ts = Utc::now();
        let ts = SmithyDateTime::from_nanos(ts.timestamp_nanos() as i128)
            .expect("failed to convert DateTime<Utc>");

        let req_cli_builder = ClientBuilder::new()
            .user_agent(env!("CARGO_PKG_NAME"))
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(15))
            .connection_verbose(true)
            .build()
            .map_err(|e| {
                Error::new(
                    ErrorKind::Other,
                    format!("failed ClientBuilder build {}", e),
                )
            })?;
        let resp = req_cli_builder
            .get(format!("{}/ext/metrics", opts.rpc_endpoint).as_str())
            .send()
            .await
            .map_err(|e| {
                Error::new(ErrorKind::Other, format!("failed ClientBuilder send {}", e))
            })?;
        let out = resp.bytes().await.map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed ClientBuilder bytes {}", e),
            )
        })?;
        let out: Vec<u8> = out.into();

        let s = match prometheus_manager::Scrape::from_bytes(&out) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("failed scrape {}, retrying...", e);
                continue;
            }
        };

        // reload everytime in case rules are updated
        let metrics_rules = prometheus_manager::Rules::load(&opts.rules_file_path)?;

        let cur_metrics = match prometheus_manager::apply_rules(&s.metrics, metrics_rules) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("failed apply_rules {}, retrying...", e);
                continue;
            }
        };
        let mut data = vec![];
        for mv in cur_metrics {
            data.push(
                MetricDatum::builder()
                    .metric_name(mv.name_with_labels())
                    .value(mv.value.to_f64())
                    .unit(StandardUnit::None)
                    .timestamp(ts)
                    .build(),
            )
        }
        match cw_manager.put_metric_data(&opts.namespace, data).await {
            Ok(_) => {}
            Err(e) => {
                log::warn!("failed to put metric data {}, retrying...", e);
                continue;
            }
        }
    }
}
