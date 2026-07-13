//! NIST ACVP known-answer tests for ML-DSA-87 (FIPS 204).
//!
//! This is the free, self-service half of NIST's validation pipeline: the
//! Cryptographic Algorithm Validation Program (CAVP) publishes the exact test
//! vectors its ACVP servers use, so we can run them locally and prove this
//! implementation matches NIST's expected outputs bit-for-bit. (Minting an
//! official certificate still requires an NVLAP-accredited lab and the
//! production ACVTS server — see `../../NIST_VALIDATION.md`.)
//!
//! Vectors are vendored, unmodified except for filtering, from
//! `usnistgov/ACVP-Server` (`gen-val/json-files/ML-DSA-*-FIPS204/
//! internalProjection.json`), restricted to `parameterSet == "ML-DSA-87"` (the
//! only set this crate implements) and, for sig{Gen,Ver}, the
//! `signatureInterface == "internal"` / `externalMu == false` groups — i.e. the
//! FIPS 204 `Sign_internal`/`Verify_internal` algorithms, which
//! `crate::sign::{signature,verify}` implement directly (no domain-separation
//! prefixing, no externally supplied `mu`).
//!
//! Mapping to FIPS 204 / this crate:
//!
//! - keyGen: `seed` (xi) -> `crate::sign::keypair`, then checks `pk`, `sk`.
//! - sigGen: `crate::sign::signature` runs `Sign_internal(sk, message, rnd)` (`rnd = 0^32` when the
//!   group is `deterministic`, else the vector's `rnd`), then checks `signature`.
//! - sigVer: `crate::sign::verify` runs `Verify_internal(pk, message, sig)` (includes
//!   intentionally-corrupted cases), then checks `testPassed`.

use alloc::vec::Vec;
use serde_json::Value;
use std::{fs, path::PathBuf};

use crate::params::{PUBLICKEYBYTES, SECRETKEYBYTES, SIGNBYTES};

/// Load a vendored ACVP vector file from `tests/acvp_vectors/`.
fn load(name: &str) -> Value {
	let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/acvp_vectors").join(name);
	let data = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {:?}: {}", path, e));
	serde_json::from_str(&data).expect("ACVP vector file is valid JSON")
}

/// Decode a hex-encoded string field (NIST uses uppercase hex; empty allowed).
fn hexs(test: &Value, key: &str) -> Vec<u8> {
	let s = test
		.get(key)
		.and_then(Value::as_str)
		.unwrap_or_else(|| panic!("missing hex field `{}`", key));
	hex::decode(s).unwrap_or_else(|e| panic!("bad hex in field `{}`: {}", key, e))
}

/// Convert a byte slice into a fixed-size array, asserting the expected length.
fn fixed<const N: usize>(bytes: &[u8], what: &str) -> [u8; N] {
	<[u8; N]>::try_from(bytes)
		.unwrap_or_else(|_| panic!("{} has wrong length {} (expected {})", what, bytes.len(), N))
}

fn groups(vs: &Value) -> &Vec<Value> {
	vs["testGroups"].as_array().expect("testGroups array")
}

fn tests(group: &Value) -> &Vec<Value> {
	group["tests"].as_array().expect("tests array")
}

fn tc_id(test: &Value) -> u64 {
	test["tcId"].as_u64().expect("tcId")
}

#[test]
fn acvp_keygen_ml_dsa_87() {
	let vs = load("keygen_ml_dsa_87.json");
	let mut count = 0usize;
	for group in groups(&vs) {
		for test in tests(group) {
			let tc = tc_id(test);
			let mut seed = fixed::<32>(&hexs(test, "seed"), "seed");
			let expected_pk = hexs(test, "pk");
			let expected_sk = hexs(test, "sk");

			let sensitive_seed = crate::SensitiveBytes32::new(&mut seed);
			let mut pk = [0u8; PUBLICKEYBYTES];
			let mut sk = [0u8; SECRETKEYBYTES];
			crate::sign::keypair(&mut pk, &mut sk, sensitive_seed);

			assert_eq!(pk.as_slice(), expected_pk.as_slice(), "keyGen tcId {} pk mismatch", tc);
			assert_eq!(sk.as_slice(), expected_sk.as_slice(), "keyGen tcId {} sk mismatch", tc);
			count += 1;
		}
	}
	assert!(count > 0, "no keyGen vectors loaded");
	std::println!("ACVP ML-DSA-87 keyGen: {} vectors OK", count);
}

#[test]
fn acvp_siggen_ml_dsa_87() {
	let vs = load("siggen_ml_dsa_87.json");
	let mut count = 0usize;
	for group in groups(&vs) {
		// Deterministic groups fix rnd = 0^32 (our `hedge = None`); hedged groups
		// supply the `rnd` per test case.
		let deterministic = group["deterministic"].as_bool().expect("deterministic flag");
		for test in tests(group) {
			let tc = tc_id(test);
			let message = hexs(test, "message");
			let sk = fixed::<SECRETKEYBYTES>(&hexs(test, "sk"), "sk");
			let expected_sig = hexs(test, "signature");
			let hedge =
				if deterministic { None } else { Some(fixed::<32>(&hexs(test, "rnd"), "rnd")) };

			let mut sig = [0u8; SIGNBYTES];
			// The internal (Sign_internal) API hashes the message directly, with no
			// domain prefix; pass an empty prefix.
			crate::sign::signature(&mut sig, &[], &message, &sk, hedge);

			assert_eq!(
				sig.as_slice(),
				expected_sig.as_slice(),
				"sigGen tcId {} signature mismatch (deterministic={})",
				tc,
				deterministic
			);
			count += 1;
		}
	}
	assert!(count > 0, "no sigGen vectors loaded");
	std::println!("ACVP ML-DSA-87 sigGen: {} vectors OK", count);
}

#[test]
fn acvp_sigver_ml_dsa_87() {
	let vs = load("sigver_ml_dsa_87.json");
	let mut count = 0usize;
	for group in groups(&vs) {
		for test in tests(group) {
			let tc = tc_id(test);
			let pk = fixed::<PUBLICKEYBYTES>(&hexs(test, "pk"), "pk");
			let message = hexs(test, "message");
			let expected = test["testPassed"].as_bool().expect("testPassed");

			// A length-mutated signature cannot verify; treat as rejection.
			let sig_bytes = hexs(test, "signature");
			let got = match <[u8; SIGNBYTES]>::try_from(sig_bytes.as_slice()) {
				Ok(sig) => crate::sign::verify(&sig, &[], &message, &pk),
				Err(_) => false,
			};

			assert_eq!(
				got,
				expected,
				"sigVer tcId {} expected testPassed={} got {} (reason: {})",
				tc,
				expected,
				got,
				test["reason"].as_str().unwrap_or("")
			);
			count += 1;
		}
	}
	assert!(count > 0, "no sigVer vectors loaded");
	std::println!("ACVP ML-DSA-87 sigVer: {} vectors OK", count);
}
