#!/usr/bin/env bash
# Run the same clippy command as CI (see .github/workflows/ci.yml)
set -euo pipefail

taplo format
cargo +nightly fmt --all
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

