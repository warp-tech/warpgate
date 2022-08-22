#!/bin/sh
set -e
cd ..
rm target/llvm-cov-target/* || true
cargo llvm-cov clean --workspace
cargo llvm-cov --no-report --workspace --all-features
cd tests
poetry run pytest -s $@
cargo llvm-cov --no-run --hide-instantiations --html
