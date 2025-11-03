#!/usr/bin/env bash
set -euo pipefail

# verify_kat_sign.sh
# Runs the Rust Dilithium KAT verifier against a KAT .rsp file.
# Usage:
#   scripts/verify_kat_sign.sh [PATH_TO_KAT_RSP]
#
# Optional env:
#   RUST_DEBUG_SIG=1   # print detailed Rust signing debug for count 0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DEFAULT_KAT="${REPO_ROOT}/../pq-crystals-dilithium/ref/nistkat/PQCsignKAT_Dilithium5.rsp"
KAT_PATH="${1:-$DEFAULT_KAT}"

if [[ ! -f "${KAT_PATH}" ]]; then
  echo "KAT file not found: ${KAT_PATH}" >&2
  exit 1
fi

cd "${REPO_ROOT}"

echo "Running Rust KAT verifier against: ${KAT_PATH}"
env -u RUSTC_WRAPPER cargo run --example verify_kat_sign \
  --package qp-rusty-crystals-dilithium -- "${KAT_PATH}"


