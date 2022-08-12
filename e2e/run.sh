#!/bin/sh
set -e
cd ..
rm target/llvm-cov-target/* || true
cargo llvm-cov clean --workspace
cargo llvm-cov --no-report --workspace
cd e2e
poetry run pytest $@
cargo llvm-cov --no-run --hide-instantiations --html
