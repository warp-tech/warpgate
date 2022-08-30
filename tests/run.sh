#!/bin/sh
set -e
cd ..
rm target/llvm-cov-target/* || true
cargo llvm-cov clean --workspace
cargo llvm-cov --no-report --workspace --all-features -- --skip agent
cd tests
RUST_BACKTRACE=1 poetry run pytest $@
cargo llvm-cov --no-run --hide-instantiations --html
