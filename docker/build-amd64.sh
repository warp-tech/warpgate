#!/usr/bin/env bash
# Builds an amd64 Warpgate image on an arm64 host (e.g. Apple Silicon) without
# emulation: the web UI is built natively, the binary is cross-compiled
# natively, and only the final COPY-only image is amd64.
#
# Downloads and compiled crates are kept in podman volumes (warpgate-*), so
# rebuilds only recompile what changed.
#
# Usage: docker/build-amd64.sh <image:tag> [--push]
# Env:   JOBS (parallel rustc jobs, default 4), CARGO_PROFILE (default release-no-lto)
set -euo pipefail

cd "$(dirname "$0")/.."

IMAGE=${1:?usage: docker/build-amd64.sh <image:tag> [--push]}
PUSH=${2:-}
JOBS=${JOBS:-4}
PROFILE=${CARGO_PROFILE:-release-no-lto}
TARGET=x86_64-unknown-linux-gnu
OUT=.build-amd64
FEATURES=mysql,postgres,rdp-openssl-tls

started=$(date +%s)

echo "==> [1/3] Building the web UI"
podman run --rm \
    -v "$PWD":/src \
    -v warpgate-node-modules:/src/warpgate-web/node_modules \
    -v warpgate-npm-cache:/root/.npm \
    -w /src/warpgate-web \
    docker.io/library/node:24-bookworm \
    bash -euc '
        if ! command -v java >/dev/null; then
            apt-get update -qq
            apt-get install -y -qq --no-install-recommends default-jre-headless >/dev/null
        fi
        npm ci --no-audit --no-fund
        npm run build
    '

echo "==> [2/3] Cross-compiling warpgate for $TARGET ($PROFILE)"
podman run --rm \
    -v "$PWD":/src \
    -v warpgate-cargo-registry:/usr/local/cargo/registry \
    -v warpgate-rustup:/usr/local/rustup \
    -v warpgate-target-amd64:/target \
    -e CARGO_TARGET_DIR=/target \
    -e SOURCE_DATE_EPOCH=0 \
    -w /src \
    docker.io/library/rust:1-bookworm \
    bash -euc "
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends \
            gcc-x86-64-linux-gnu g++-x86-64-linux-gnu libc6-dev-amd64-cross \
            clang cmake perl make >/dev/null
        git config --global --add safe.directory /src
        rustup show active-toolchain >/dev/null 2>&1 || rustup toolchain install
        rustup target add $TARGET

        export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc
        export CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc
        export CXX_x86_64_unknown_linux_gnu=x86_64-linux-gnu-g++
        export AR_x86_64_unknown_linux_gnu=x86_64-linux-gnu-ar

        cargo build --target $TARGET --profile $PROFILE --features $FEATURES -j $JOBS \
            --config 'profile.$PROFILE.package.aws-sdk-ec2.opt-level=1' \
            --config 'profile.$PROFILE.package.aws-sdk-rds.opt-level=1' \
            --config 'profile.$PROFILE.package.aws-sdk-eks.opt-level=1' \
            --config 'profile.$PROFILE.package.aws-sdk-s3.opt-level=1'

        mkdir -p $OUT
        cp /target/$TARGET/$PROFILE/warpgate $OUT/warpgate
    "

echo "==> [3/3] Packaging $IMAGE (linux/amd64)"
mkdir -p "$OUT/data"
printf '%s\n' \
    'root:x:0:0:root:/root:/sbin/nologin' \
    'nobody:x:65534:65534:nobody:/nonexistent:/sbin/nologin' \
    'warpgate:x:1000:1000::/data:/usr/sbin/nologin' >"$OUT/passwd"
printf '%s\n' \
    'root:x:0:' \
    'nogroup:x:65534:' \
    'warpgate:x:1000:' >"$OUT/group"

podman build --platform linux/amd64 -f docker/Dockerfile.cross -t "$IMAGE" "$OUT"

if [[ "$PUSH" == "--push" ]]; then
    echo "==> Pushing $IMAGE"
    podman push "$IMAGE"
fi

echo "==> Done in $(( ($(date +%s) - started) / 60 )) min: $IMAGE"
