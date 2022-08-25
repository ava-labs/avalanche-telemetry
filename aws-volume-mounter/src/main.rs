pub mod command;

use std::io;

pub const APP_NAME: &str = "aws-volume-mounter";

#[tokio::main]
async fn main() -> io::Result<()> {
    let matches = command::new().get_matches();

    let log_level = matches.value_of("LOG_LEVEL").unwrap_or("info").to_string();
    let aws_region = matches
        .value_of("AWS_REGION")
        .unwrap_or("us-west-2")
        .to_string();

    let ebs_volume_id = {
        if let Some(v) = matches.value_of("EBS_VOLUME_ID") {
            Some(v.to_string())
        } else {
            None
        }
    };

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
        aws_region,
        ebs_volume_id,
        ebs_device_name,
        block_device_name,
        filesystem_name,
        mount_directory_path,
    };
    command::execute(opts).await
}
