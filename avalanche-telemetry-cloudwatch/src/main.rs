pub mod command;

use std::io;

pub const APP_NAME: &str = "avalanche-telemetry-cloudwatch";

#[tokio::main]
async fn main() -> io::Result<()> {
    let matches = command::new().get_matches();

    let log_level = matches
        .get_one::<String>("LOG_LEVEL")
        .unwrap_or(&String::from("info"))
        .clone();

    let initial_wait_seconds = matches
        .get_one::<u32>("INITIAL_WAIT_SECONDS")
        .unwrap_or(&5)
        .clone();

    let fetch_interval_seconds = matches
        .get_one::<u32>("FETCH_INTERVAL_SECONDS")
        .unwrap_or(&60)
        .clone();

    let opts = command::Flags {
        log_level,
        initial_wait_seconds,
        fetch_interval_seconds,

        rules_file_path: matches
            .get_one::<String>("RULES_FILE_PATH")
            .unwrap_or(&String::from(
                "/data/avalanche-telemetry-cloudwatch.rules.yaml",
            ))
            .clone(),
        namespace: matches
            .get_one::<String>("NAMESPACE")
            .unwrap_or(&String::from("avalanche-telemetry-cloudwatch"))
            .clone(),

        rpc_endpoint: matches
            .get_one::<String>("RPC_ENDPOINT")
            .unwrap_or(&String::from("http://localhost:9650"))
            .clone(),
    };
    command::execute(opts).await
}
