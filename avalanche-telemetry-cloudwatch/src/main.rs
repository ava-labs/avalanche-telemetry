pub mod command;

use std::io;

pub const APP_NAME: &str = "avalanche-telemetry-cloudwatch";

#[tokio::main]
async fn main() -> io::Result<()> {
    let matches = command::new().get_matches();

    let log_level = matches.value_of("LOG_LEVEL").unwrap_or("info").to_string();

    let initial_wait_random_seconds = matches
        .value_of("INITIAL_WAIT_RANDOM_SECONDS")
        .unwrap_or("0");
    let initial_wait_random_seconds = initial_wait_random_seconds.parse::<u32>().unwrap();

    let kind = matches.value_of("KIND_TAG").unwrap().to_string();
    let id = matches.value_of("ID_TAG").unwrap().to_string();

    let volume_type = matches.value_of("VOLUME_TYPE").unwrap_or("gp3").to_string();
    let volume_size = matches.value_of("VOLUME_SIZE").unwrap_or("400");
    let volume_size = volume_size.parse::<i32>().unwrap();

    let volume_iops = matches.value_of("VOLUME_IOPS").unwrap_or("3000");
    let volume_iops = volume_iops.parse::<i32>().unwrap();

    let volume_throughput = matches.value_of("VOLUME_THROUGHPUT").unwrap_or("500");
    let volume_throughput = volume_throughput.parse::<i32>().unwrap();

    let ebs_device_name = matches
        .value_of("EBS_DEVICE_NAME")
        .unwrap_or("/dev/xvdb")
        .to_string();
    let block_device_name = matches
        .value_of("BLOCK_DEVICE_NAME")
        .unwrap_or("/dev/nvme1n1")
        .to_string();
    let filesystem_name = matches
        .value_of("FILESYSTEM_NAME")
        .unwrap_or("ext4")
        .to_string();
    let mount_directory_path = matches
        .value_of("MOUNT_DIRECTORY_PATH")
        .unwrap_or("/data")
        .to_string();

    let opts = command::Flags {
        log_level,
        initial_wait_random_seconds,
        kind,
        id,
        volume_type,
        volume_size,
        volume_iops,
        volume_throughput,
        ebs_device_name,
        block_device_name,
        filesystem_name,
        mount_directory_path,
    };
    command::execute(opts).await
}
