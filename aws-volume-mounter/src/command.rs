use std::{
    fs,
    io::{self, Error, ErrorKind},
};

use aws_manager::{self, ec2};
use aws_sdk_ec2::model::VolumeAttachmentState;
use clap::{crate_version, Arg, Command};
use tokio::time::Duration;

pub const NAME: &str = "aws-volume-mounter";

pub fn new() -> Command<'static> {
    Command::new(NAME)
        .version(crate_version!())
        .about("Mounts the EBS volume to the local EC2 instance")
        .long_about(
            "

The local instance Id is automatically fetched (if needed for queries).

Commands may run multiple times with idempotency.

e.g.,

$ aws-volume-mounter \
--log-level=info \
--aws-region=us-west-2 \
--ebs-device-name=/dev/xvdb \
--block-device-name=/dev/nvme1n1 \
--filesystem-name=ext4 \
--mount-directory-path=/data

$ aws-volume-mounter \
--log-level=info \
--aws-region=us-west-2 \
--ebs-volume-id=test-abcdefgh \
--block-device-name=/dev/nvme1n1 \
--filesystem-name=ext4 \
--mount-directory-path=/data

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
            Arg::new("AWS_REGION")
                .long("aws-region")
                .short('r')
                .help("Sets the AWS region")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        // optional
        .arg(
            Arg::new("EBS_VOLUME_ID")
                .long("ebs-volume-id")
                .short('v')
                .help("Sets the EBS volume Id (fetched automatic if none)")
                .required(false)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("EBS_DEVICE_NAME")
                .long("ebs-device-name")
                .short('d')
                .help("Sets the EBS device name (e.g., /dev/xvdb)")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("BLOCK_DEVICE_NAME")
                .long("block-device-name")
                .short('b')
                .help("Sets the OS-level block device name (e.g., /dev/nvme1n1)")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("FILESYSTEM_NAME")
                .long("filesystem-name")
                .short('f')
                .help("Sets the filesystem name to create (e.g., ext4)")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("MOUNT_DIRECTORY_PATH")
                .long("mount-directory-path")
                .short('m')
                .help("Sets the directory path to mount onto the device")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
}

/// Defines flag options.
pub struct Flags {
    pub log_level: String,
    pub aws_region: String,
    pub ebs_volume_id: Option<String>,
    pub ebs_device_name: String,
    pub block_device_name: String,
    pub filesystem_name: String,
    pub mount_directory_path: String,
}

pub async fn execute(opts: Flags) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opts.log_level),
    );
    log::info!("starting 'aws-volume-mounter'");

    let shared_config = aws_manager::load_config(Some(opts.aws_region)).await?;
    let ec2_manager = ec2::Manager::new(&shared_config);

    let volume = ec2_manager
        .poll_local_volume_by_attachment_state(
            opts.ebs_volume_id,
            opts.ebs_device_name,
            VolumeAttachmentState::Attached,
            Duration::from_secs(180),
            Duration::from_secs(10),
        )
        .await
        .map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed poll_local_volume_by_attachment_state '{}'", e),
            )
        })?;
    log::info!("successfully polled volume {:?}", volume);

    ec2::disk::make_filesystem(&opts.filesystem_name, &opts.block_device_name)?;

    log::info!("mkdir {}", opts.mount_directory_path);
    fs::create_dir_all(&opts.mount_directory_path)?;

    ec2::disk::mount_filesystem(
        &opts.filesystem_name,
        &opts.block_device_name,
        &opts.mount_directory_path,
    )?;

    ec2::disk::update_fstab(
        &opts.filesystem_name,
        &opts.block_device_name,
        &opts.mount_directory_path,
    )?;

    log::info!("mounting all");
    command_manager::run("sudo mount --all")?;

    let (blk_lists, _) = command_manager::run("lsblk")?;
    println!("\n\n'lsblk' output:\n\n{}\n", blk_lists);
    assert!(blk_lists.contains(strip_dev(&opts.block_device_name)));
    assert!(blk_lists.contains(&opts.mount_directory_path));

    let (df_output, _) = command_manager::run("df -h")?;
    println!("\n\n'df -h' output:\n\n{}\n", df_output);
    assert!(df_output.contains(strip_dev(&opts.block_device_name)));
    assert!(df_output.contains(&opts.mount_directory_path));

    log::info!("successfully mounted the volume!");
    Ok(())
}

pub fn strip_dev(s: &str) -> &str {
    if s.len() >= 5 && &s[0..5] == "/dev/" {
        &s[5..]
    } else {
        s
    }
}
