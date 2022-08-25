#!/usr/bin/env bash
set -xue

if ! [[ "$0" =~ scripts/build.release.sh ]]; then
  echo "must be run from repository root"
  exit 255
fi

# "--bin" can be specified multiple times for each directory in "bin/*" or workspaces
cargo build \
--release \
--bin aws-volume-mounter \
--bin aws-volume-provisioner

./target/release/aws-volume-mounter --help
./target/release/aws-volume-provisioner --help
