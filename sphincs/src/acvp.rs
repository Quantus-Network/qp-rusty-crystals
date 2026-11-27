//! NIST ACVP known-answer tests for all FIPS 205 parameter sets: keyGen,
//! sigGen and sigVer over the internal, pure and pre-hash interfaces.
//! `tests/acvp_vectors/update.sh` builds the vector files.

use alloc::{vec, vec::Vec};
use serde_json::Value;
use sha2::Digest;
use sha3::digest::{ExtendableOutput, XofReader};
use std::{fs, path::PathBuf};

use crate::PreHash;

fn load(name: &str) -> Value {
	let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/acvp_vectors").join(name);
	let data = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
	serde_json::from_str(&data).expect("vector file is valid JSON")
}

fn groups(file: &Value) -> &Vec<Value> {
	file["testGroups"].as_array().expect("testGroups")
}

fn tests(group: &Value) -> &Vec<Value> {
	group["tests"].as_array().expect("tests")
}

fn text<'v>(value: &'v Value, key: &str) -> &'v str {
	value[key].as_str().unwrap_or_else(|| panic!("missing field {key}"))
}

fn bytes(test: &Value, key: &str) -> Vec<u8> {
	hex::decode(text(test, key)).unwrap_or_else(|e| panic!("bad hex in {key}: {e}"))
}

fn optional_bytes(test: &Value, key: &str) -> Option<Vec<u8>> {
	test.get(key).map(|_| bytes(test, key))
}

fn xof(mut hasher: impl ExtendableOutput, message: &[u8], out_bytes: usize) -> Vec<u8> {
	hasher.update(message);
	let mut out = vec![0u8; out_bytes];
	hasher.finalize_xof().read(&mut out);
	out
}

fn pre_hash(name: &str, message: &[u8]) -> (PreHash, Vec<u8>) {
	match name {
		"SHA2-224" => (PreHash::Sha2_224, sha2::Sha224::digest(message).to_vec()),
		"SHA2-256" => (PreHash::Sha2_256, sha2::Sha256::digest(message).to_vec()),
		"SHA2-384" => (PreHash::Sha2_384, sha2::Sha384::digest(message).to_vec()),
		"SHA2-512" => (PreHash::Sha2_512, sha2::Sha512::digest(message).to_vec()),
		"SHA2-512/224" => (PreHash::Sha2_512_224, sha2::Sha512_224::digest(message).to_vec()),
		"SHA2-512/256" => (PreHash::Sha2_512_256, sha2::Sha512_256::digest(message).to_vec()),
		"SHA3-224" => (PreHash::Sha3_224, sha3::Sha3_224::digest(message).to_vec()),
		"SHA3-256" => (PreHash::Sha3_256, sha3::Sha3_256::digest(message).to_vec()),
		"SHA3-384" => (PreHash::Sha3_384, sha3::Sha3_384::digest(message).to_vec()),
		"SHA3-512" => (PreHash::Sha3_512, sha3::Sha3_512::digest(message).to_vec()),
		"SHAKE-128" => (PreHash::Shake128, xof(sha3::Shake128::default(), message, 32)),
		"SHAKE-256" => (PreHash::Shake256, xof(sha3::Shake256::default(), message, 64)),
		other => panic!("unknown pre-hash {other}"),
	}
}

macro_rules! acvp_tests {
	($module:ident, $file:literal) => {
		mod $module {
			use super::*;
			use crate::{
				slh,
				$module::{Keypair, PublicKey, SecretKey, ALGORITHM, N, PARAMS, SIGNBYTES},
			};

			#[test]
			#[cfg_attr(debug_assertions, ignore = "slow without optimizations")]
			fn keygen() {
				let file = load("keygen.json");
				let group = groups(&file)
					.iter()
					.find(|group| text(group, "parameterSet") == ALGORITHM)
					.expect("group for the parameter set");
				assert_eq!(tests(group).len(), 10);
				for test in tests(group) {
					let mut seed =
						[bytes(test, "skSeed"), bytes(test, "skPrf"), bytes(test, "pkSeed")]
							.concat()
							.try_into()
							.expect("seed length");
					let keypair = Keypair::generate(&mut seed);
					assert_eq!(keypair.secret().to_bytes()[..], bytes(test, "sk")[..]);
					assert_eq!(keypair.public().bytes[..], bytes(test, "pk")[..]);
					assert_eq!(seed, [0u8; 3 * N]);
				}
			}

			fn check_siggen(group: &Value) {
				let interface = (text(group, "signatureInterface"), text(group, "preHash"));
				let deterministic = group["deterministic"].as_bool().expect("deterministic");
				for test in tests(group) {
					let id = &test["tcId"];
					let sk = bytes(test, "sk");
					let secret = SecretKey::from_bytes(&sk).expect("valid secret key");
					let message = bytes(test, "message");
					let context = optional_bytes(test, "context");
					let addrnd: Option<[u8; N]> = optional_bytes(test, "additionalRandomness")
						.map(|bytes| bytes.try_into().expect("randomness length"));
					assert_eq!(addrnd.is_none(), deterministic, "tcId {id}");

					let sig = match interface {
						("internal", "none") => {
							let mut sig = vec![0u8; SIGNBYTES];
							let addrnd = addrnd.as_ref().map(|bytes| &bytes[..]);
							slh::sign(PARAMS, &sk, &[&message], addrnd, &mut sig);
							sig
						},
						("external", "pure") => secret
							.sign(&message, context.as_deref(), addrnd.as_ref())
							.expect("signing")
							.to_vec(),
						("external", "preHash") => {
							let (pre_hash, digest) = pre_hash(text(test, "hashAlg"), &message);
							secret
								.sign_prehash(
									pre_hash,
									&digest,
									context.as_deref(),
									addrnd.as_ref(),
								)
								.expect("signing")
								.to_vec()
						},
						other => panic!("unknown interface {other:?}"),
					};
					assert_eq!(
						hex::encode(sha2::Sha256::digest(&sig)),
						text(test, "signatureSha256"),
						"tcId {id}"
					);
				}
			}

			#[test]
			#[cfg_attr(debug_assertions, ignore = "slow without optimizations")]
			fn siggen() {
				let file = load(concat!("siggen_", $file, ".json"));
				let total: usize = groups(&file).iter().map(|group| tests(group).len()).sum();
				assert_eq!(total, 52);
				std::thread::scope(|scope| {
					for group in groups(&file) {
						scope.spawn(|| check_siggen(group));
					}
				});
			}

			#[test]
			fn sigver() {
				let file = load(concat!("sigver_", $file, ".json"));
				let mut total = 0;
				for group in groups(&file) {
					let interface = (text(group, "signatureInterface"), text(group, "preHash"));
					for test in tests(group) {
						let pk = bytes(test, "pk");
						let public = PublicKey::from_bytes(&pk).expect("valid public key");
						let message = bytes(test, "message");
						let context = optional_bytes(test, "context");
						let sig = bytes(test, "signature");
						let valid = match interface {
							("internal", "none") => slh::verify(PARAMS, &pk, &[&message], &sig),
							("external", "pure") =>
								public.verify(&message, &sig, context.as_deref()),
							("external", "preHash") => {
								let (pre_hash, digest) = pre_hash(text(test, "hashAlg"), &message);
								public.verify_prehash(pre_hash, &digest, &sig, context.as_deref())
							},
							other => panic!("unknown interface {other:?}"),
						};
						assert_eq!(
							valid,
							test["testPassed"].as_bool().expect("testPassed"),
							"tcId {} ({})",
							test["tcId"],
							text(test, "reason")
						);
						total += 1;
					}
				}
				assert_eq!(total, 42);
			}
		}
	};
}

acvp_tests!(slh_dsa_sha2_128s, "sha2_128s");
acvp_tests!(slh_dsa_shake_128s, "shake_128s");
acvp_tests!(slh_dsa_sha2_128f, "sha2_128f");
acvp_tests!(slh_dsa_shake_128f, "shake_128f");
acvp_tests!(slh_dsa_sha2_192s, "sha2_192s");
acvp_tests!(slh_dsa_shake_192s, "shake_192s");
acvp_tests!(slh_dsa_sha2_192f, "sha2_192f");
acvp_tests!(slh_dsa_shake_192f, "shake_192f");
acvp_tests!(slh_dsa_sha2_256s, "sha2_256s");
acvp_tests!(slh_dsa_shake_256s, "shake_256s");
acvp_tests!(slh_dsa_sha2_256f, "sha2_256f");
acvp_tests!(slh_dsa_shake_256f, "shake_256f");
