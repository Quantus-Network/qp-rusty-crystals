#!/usr/bin/env bash
set -euo pipefail

# Default workspace features (dilithium: ML-DSA-87).
cargo test --workspace -- --test-threads 16

# Full dilithium feature matrix: ACVP KATs for ML-DSA-44/65/87.
cargo test -p qp-rusty-crystals-dilithium --all-features -- --test-threads 16

# HD wallet modules coexist, but default tests only enable 87.
# Exclusive-feature runs cover 44 and 65 (mirrors CI).
for variant in ml-dsa-44 ml-dsa-65; do
	echo "=== $variant exclusive ==="
	cargo test -p qp-rusty-crystals-hdwallet --no-default-features --features "std,$variant" -- --test-threads 16
done
