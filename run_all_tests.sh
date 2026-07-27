#!/usr/bin/env bash
set -euo pipefail

# Default workspace features (dilithium: ML-DSA-87).
cargo test --workspace -- --test-threads 16

# Full dilithium feature matrix: ACVP KATs for ML-DSA-44/65/87.
cargo test -p qp-rusty-crystals-dilithium --all-features -- --test-threads 16
