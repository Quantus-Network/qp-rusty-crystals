#!/usr/bin/env bash
# Run the same clippy command as CI (see .github/workflows/ci.yml)
set -euo pipefail

cargo +nightly fmt
taplo format
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
