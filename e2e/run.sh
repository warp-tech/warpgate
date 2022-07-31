#!/bin/sh
set -e
cd ..
cargo llvm-cov clean --workspace
cargo llvm-cov --no-report --workspace
cd e2e
poetry run pytest
