#!/bin/sh
set -e
cd ..
# The out-of-workspace RDP helper must be prebuilt: warpgate-protocol-rdp's build script
# embeds it, and the build fails without it (there is no runtime PATH fallback).
just build-rdp-helper
rm target/llvm-cov-target/* || true
cargo llvm-cov clean --workspace
cargo llvm-cov --no-cfg-coverage-nightly --no-report --workspace --all-features -- --skip agent
cd tests
RUST_BACKTRACE=1 ENABLE_COVERAGE=1 poetry run pytest --timeout 300 $@
cargo llvm-cov report --html
