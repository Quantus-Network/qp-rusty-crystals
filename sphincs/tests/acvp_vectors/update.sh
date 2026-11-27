#!/usr/bin/env bash
# Rebuilds the vector files from NIST's ACVP-Server. Needs curl, jq, xxd and shasum.
# sigGen signatures are stored as their SHA-256 digest to keep the files small.
set -euo pipefail

TAG="${1:-v1.1.0.43}"
BASE="https://raw.githubusercontent.com/usnistgov/ACVP-Server/$TAG/gen-val/json-files"
OUT="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

for mode in keyGen sigGen sigVer; do
	curl -sSfL "$BASE/SLH-DSA-$mode-FIPS205/internalProjection.json" -o "$TMP/$mode.json"
done

jq -c '{testGroups: [.testGroups[] | {parameterSet, tests: [.tests[] | {tcId, skSeed, skPrf, pkSeed, sk, pk}]}]}' \
	"$TMP/keyGen.json" > "$OUT/keygen.json"

jq -r '.testGroups[].tests[] | "\(.tcId) \(.signature)"' "$TMP/sigGen.json" |
	while read -r id signature; do
		digest="$(printf %s "$signature" | xxd -r -p | shasum -a 256 | cut -c1-64)"
		printf '{"%s": "%s"}\n' "$id" "$digest"
	done | jq -s add > "$TMP/digests.json"

for set in $(jq -r '.testGroups[].parameterSet' "$TMP/keyGen.json"); do
	name="$(printf %s "${set#SLH-DSA-}" | tr 'A-Z-' 'a-z_')"
	jq -c --arg set "$set" --slurpfile digests "$TMP/digests.json" '
		{testGroups: [.testGroups[] | select(.parameterSet == $set) | {
			signatureInterface, preHash, deterministic,
			tests: [.tests[] | {
				tcId, sk, message, context, hashAlg, additionalRandomness,
				signatureSha256: $digests[0][.tcId | tostring]
			} | with_entries(select(.value != null))]
		}]}' "$TMP/sigGen.json" > "$OUT/siggen_$name.json"
	jq -c --arg set "$set" '
		{testGroups: [.testGroups[] | select(.parameterSet == $set) | {
			signatureInterface, preHash,
			tests: [.tests[] | {
				tcId, pk, message, context, hashAlg, signature, testPassed, reason
			} | with_entries(select(.value != null))]
		}]}' "$TMP/sigVer.json" > "$OUT/sigver_$name.json"
done
