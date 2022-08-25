use std::{
    env, fs,
    io::{self, Error, ErrorKind},
    path::{Path, PathBuf},
};

use aws_manager::{self, ec2};
use aws_sdk_ec2::model::{
    Filter, ResourceType, Tag, TagSpecification, VolumeAttachmentState, VolumeState, VolumeType,
};
use clap::{crate_version, Arg, Command};
use path_clean::PathClean;
use tokio::time::{sleep, Duration};
use walkdir::WalkDir;

pub const NAME: &str = "avalanche-telemetry-cloudwatch";

pub fn new() -> Command<'static> {
    Command::new(NAME)
        .version(crate_version!())
        .about("Provisions the EBS volume to the local availability zone")
        .long_about(
            "


The availability zone is automatically fetched.

Commands may run multiple times with idempotency.

Requires IAM instance role of: ec2:DescribeVolumes, ec2:CreateVolume, and ec2:AttachVolume.

e.g.,

$ avalanche-telemetry-cloudwatch \
--log-level=info \
--initial-wait-random-seconds=70 \
--kind-tag=avalanche-telemetry-cloudwatch \
--id-tag=TEST-ID \
--volume-type=gp3 \
--volume-size=400 \
--volume-iops=3000 \
--volume-throughput=500 \
--ebs-device-name=/dev/xvdb \
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
            Arg::new("INITIAL_WAIT_RANDOM_SECONDS")
            .long("initial-wait-random-seconds")
            .help("Sets the maximum number of seconds to wait (value chosen at random with the range)")
            .required(false)
            .takes_value(true)
            .allow_invalid_utf8(false)
            .default_value("0"),
        )
        .arg(
            Arg::new("KIND_TAG")
                .long("kind-tag")
                .help("Sets the kind tag")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("ID_TAG")
                .long("id-tag")
                .help("Sets the Id tag")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("VOLUME_TYPE")
                .long("volume-type")
                .help("Sets the volume size in GB")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("VOLUME_SIZE")
                .long("volume-size")
                .help("Sets the volume size in GB")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("VOLUME_IOPS")
                .long("volume-iops")
                .help("Sets the volume IOPS")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("VOLUME_THROUGHPUT")
                .long("volume-throughput")
                .help("Sets the volume throughput")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("EBS_DEVICE_NAME")
                .long("ebs-device-name")
                .help("Sets the EBS device name (e.g., /dev/xvdb)")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("BLOCK_DEVICE_NAME")
                .long("block-device-name")
                .help("Sets the OS-level block device name (e.g., /dev/nvme1n1)")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("FILESYSTEM_NAME")
                .long("filesystem-name")
                .help("Sets the filesystem name to create (e.g., ext4)")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
        .arg(
            Arg::new("MOUNT_DIRECTORY_PATH")
                .long("mount-directory-path")
                .help("Sets the directory path to mount onto the device")
                .required(true)
                .takes_value(true)
                .allow_invalid_utf8(false),
        )
}

/// Defines flag options.
pub struct Flags {
    pub log_level: String,
    pub initial_wait_random_seconds: u32,

    pub kind: String,
    pub id: String,

    pub volume_type: String,
    pub volume_size: i32,
    pub volume_iops: i32,
    pub volume_throughput: i32,

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
    log::info!("starting 'avalanche-telemetry-cloudwatch'");

    let shared_config = aws_manager::load_config(None).await?;
    let ec2_manager = ec2::Manager::new(&shared_config);
    let ec2_cli = ec2_manager.client();

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

    let sleep_sec = if opts.initial_wait_random_seconds > 0 {
        random_manager::u32() % opts.initial_wait_random_seconds
    } else {
        0
    };
    if sleep_sec > 0 {
        log::info!("waiting for random seconds {}", sleep_sec);
        sleep(Duration::from_secs(sleep_sec as u64)).await;
    } else {
        log::info!("skipping random sleep...");
    }

    log::info!(
        "checking if the local instance has an already attached volume with region '{:?}', AZ '{}', device '{}', instance Id '{}', and Id '{}' (for reuse)",
        shared_config.region(),
        az,
        opts.ebs_device_name,
        ec2_instance_id,
        opts.id
    );

    // ref. https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVolumes.html
    let filters: Vec<Filter> = vec![
        Filter::builder()
            .set_name(Some(String::from("attachment.device")))
            .set_values(Some(vec![opts.ebs_device_name.clone()]))
            .build(),
        // ensures the call only returns the volume that is attached to this local instance
        Filter::builder()
            .set_name(Some(String::from("attachment.instance-id")))
            .set_values(Some(vec![ec2_instance_id.clone()]))
            .build(),
        // ensures the call only returns the volume that is currently attached
        Filter::builder()
            .set_name(Some(String::from("attachment.status")))
            .set_values(Some(vec![String::from("attached")]))
            .build(),
        // ensures the call only returns the volume that is currently in use
        Filter::builder()
            .set_name(Some(String::from("status")))
            .set_values(Some(vec![String::from("in-use")]))
            .build(),
        Filter::builder()
            .set_name(Some(String::from("availability-zone")))
            .set_values(Some(vec![az.clone()]))
            .build(),
        Filter::builder()
            .set_name(Some(String::from("tag:Kind")))
            .set_values(Some(vec![opts.kind.clone()]))
            .build(),
        Filter::builder()
            .set_name(Some(String::from("tag:Id")))
            .set_values(Some(vec![opts.id.clone()]))
            .build(),
        Filter::builder()
            .set_name(Some(String::from("volume-type")))
            .set_values(Some(vec![opts.volume_type.clone()]))
            .build(),
    ];
    let volumes = ec2_manager
        .describe_volumes(Some(filters))
        .await
        .map_err(|e| Error::new(ErrorKind::Other, format!("failed describe_volumes '{}'", e)))?;

    log::info!("found {} attached volume", volumes.len());

    // only make filesystem (format) for initial creation
    // do not format volume for already attached EBS volumes
    // do not format volume for reused EBS volumes
    let mut need_mkfs = true;

    let attached_volume_exists = volumes.len() == 1;
    if attached_volume_exists {
        need_mkfs = false;
        log::info!("no need mkfs because the local EC2 instance already has an volume attached");
    } else {
        log::info!("local EC2 instance '{}' has no attached volume, querying available volumes by AZ '{}' and Id '{}'", ec2_instance_id, az, opts.id);

        // ref. https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVolumes.html
        let filters: Vec<Filter> = vec![
            // ensures the call only returns the volume that is currently available
            Filter::builder()
                .set_name(Some(String::from("status")))
                .set_values(Some(vec![String::from("available")]))
                .build(),
            Filter::builder()
                .set_name(Some(String::from("availability-zone")))
                .set_values(Some(vec![az.clone()]))
                .build(),
            Filter::builder()
                .set_name(Some(String::from("tag:Kind")))
                .set_values(Some(vec![opts.kind.clone()]))
                .build(),
            Filter::builder()
                .set_name(Some(String::from("tag:Id")))
                .set_values(Some(vec![opts.id.clone()]))
                .build(),
            Filter::builder()
                .set_name(Some(String::from("volume-type")))
                .set_values(Some(vec![opts.volume_type.clone()]))
                .build(),
        ];
        let mut volumes = ec2_manager
            .describe_volumes(Some(filters))
            .await
            .map_err(|e| {
                Error::new(ErrorKind::Other, format!("failed describe_volumes '{}'", e))
            })?;

        if !volumes.is_empty() {
            // TODO: this can be racey when the other instance in the same AZ is in the process of provisioning
            need_mkfs = false;
            log::info!("no need mkfs because we are attaching the existing available volume to the local EC2 instance");
            log::info!("found available volume for AZ '{}' and Id '{}', attaching '{:?}' to the local EC2 instance", az, opts.id, volumes[0]);
        } else {
            log::info!(
                "no available volume for AZ '{}' and Id '{}', must create one in the AZ with size {}, IOPS {}, throughput {}",
                az,
                opts.id,
                opts.volume_size,
                opts.volume_iops,
                opts.volume_throughput,
            );

            log::info!("sending 'create_volume' request with tags");
            // ref. https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateVolume.html
            let resp = ec2_cli
                .create_volume()
                .availability_zone(az)
                .volume_type(VolumeType::from(opts.volume_type.as_str()))
                .size(opts.volume_size)
                .iops(opts.volume_iops)
                .throughput(opts.volume_throughput)
                .encrypted(true)
                .tag_specifications(
                    TagSpecification::builder()
                        .resource_type(ResourceType::Volume)
                        .tags(
                            Tag::builder()
                                .key(String::from("Kind"))
                                .value(opts.kind.clone())
                                .build(),
                        )
                        .tags(
                            Tag::builder()
                                .key(String::from("Id"))
                                .value(opts.id.clone())
                                .build(),
                        )
                        .tags(
                            Tag::builder()
                                .key(String::from("Name"))
                                .value(opts.id.clone())
                                .build(),
                        )
                        .build(),
                )
                .send()
                .await
                .unwrap();
            let volume_id = resp.volume_id().unwrap();
            log::info!("created an EBS volume '{}'", volume_id);

            sleep(Duration::from_secs(10)).await;

            let volume = ec2_manager
                .poll_volume_state(
                    volume_id.to_string(),
                    VolumeState::Available,
                    Duration::from_secs(120),
                    Duration::from_secs(5),
                )
                .await
                .unwrap();
            log::info!("polled volume after create: {:?}", volume);

            volumes.push(volume.unwrap());
        };

        let volume_id = volumes[0].volume_id().unwrap();
        log::info!("attaching the volume {} to the local instance", volume_id);

        // ref. https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AttachVolume.html
        ec2_cli
            .attach_volume()
            .device(opts.ebs_device_name.clone())
            .volume_id(volume_id)
            .instance_id(ec2_instance_id)
            .send()
            .await
            .unwrap();
    }

    sleep(Duration::from_secs(2)).await;

    log::info!("now mount the attached EBS volume to the local EC2 instance");
    let volume = ec2_manager
        .poll_local_volume_by_attachment_state(
            None,
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

    if need_mkfs {
        ec2::disk::make_filesystem(&opts.filesystem_name, &opts.block_device_name)?;
    } else {
        log::info!("skipped mkfs to retain existing data");
    }

    log::info!("mkdir {}", opts.mount_directory_path);
    fs::create_dir_all(&opts.mount_directory_path)?;

    log::info!("sleep before mounting the file system");
    sleep(Duration::from_secs(5)).await;

    // check before mount
    let (blk_lists, _) = command_manager::run("lsblk")?;
    println!("\n\n'lsblk' output:\n\n{}\n", blk_lists);
    let (df_output, _) = command_manager::run("df -h")?;
    println!("\n\n'df -h' output:\n\n{}\n\n", df_output);

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

    // check after mount
    let (blk_lists, _) = command_manager::run("lsblk")?;
    println!("\n\n'lsblk' output:\n\n{}\n", blk_lists);
    assert!(blk_lists.contains(strip_dev(&opts.block_device_name)));
    assert!(blk_lists.contains(&opts.mount_directory_path));

    let (df_output, _) = command_manager::run("df -h")?;
    println!("\n\n'df -h' output:\n\n{}\n\n", df_output);
    assert!(df_output.contains(strip_dev(&opts.block_device_name)));
    assert!(df_output.contains(&opts.mount_directory_path));

    log::info!("walking directory {}", opts.mount_directory_path);
    let mut cnt = 0;
    for entry in WalkDir::new(&opts.mount_directory_path).into_iter() {
        let entry = match entry {
            Ok(v) => v,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed walk dir {} ({})", opts.mount_directory_path, e),
                ));
            }
        };

        let full_path = absolute_path(entry.path())?;
        log::info!("listing mounted directory: '{:?}'", full_path);
        cnt += 1;
        if cnt > 20 {
            break;
        }
    }

    log::info!("successfully mounted and provisioned the volume!");
    Ok(())
}

pub fn strip_dev(s: &str) -> &str {
    if s.len() >= 5 && &s[0..5] == "/dev/" {
        &s[5..]
    } else {
        s
    }
}

fn absolute_path(path: impl AsRef<Path>) -> io::Result<PathBuf> {
    let p = path.as_ref();

    let ap = if p.is_absolute() {
        p.to_path_buf()
    } else {
        env::current_dir()?.join(p)
    }
    .clean();

    Ok(ap)
}
