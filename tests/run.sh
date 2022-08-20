#!/bin/sh
set -e
cd ..
rm target/llvm-cov-target/* || true
cargo llvm-cov clean --workspace
cargo llvm-cov --no-report --workspace --features console-subscriber
cd tests
poetry run pytest $@
cargo llvm-cov --no-run --hide-instantiations --html
