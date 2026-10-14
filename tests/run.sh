#!/bin/sh
set -e
cd ..
rm target/llvm-cov-target/* || true
cargo llvm-cov clean --workspace
cargo llvm-cov --no-cfg-coverage-nightly --no-report --workspace --all-features -- --skip agent
# The warpgate binary the e2e nodes run. Built up front: built from a pytest
# fixture, it would count against a test's timeout on every xdist worker.
cargo llvm-cov run --no-cfg-coverage-nightly --all-features --no-report -- version
cd tests
RUST_BACKTRACE=1 ENABLE_COVERAGE=1 poetry run pytest --timeout 300 -n 4 $@
cargo llvm-cov report --lcov --output-path coverage.lcov
# The first report merged every .profraw into the .profdata; with no .profraw
# left, cargo-llvm-cov reuses that .profdata instead of merging again.
rm -f ../target/llvm-cov-target/*.profraw
cargo llvm-cov report --html
