//! SLH-DSA key derivation must leave no copy of the path entropy, `SK.seed`
//! or `SK.prf` in dead stack memory. The property depends on codegen, so the
//! probes only run in optimized builds.
#![cfg(all(not(debug_assertions), feature = "slh-dsa"))]

use qp_rusty_crystals_hdwallet::{hderive::ExtendedPrivKey, SensitiveBytes64};
use qp_rusty_crystals_test_utils::probe_stack_for_named;

const STACK_BYTES: usize = 1024 * 1024;
const SEED: [u8; 64] = *b"slh-dsa-probe-seed-first-half-0Aslh-dsa-probe-seed-second-half0B";
const MNEMONIC: &str =
	"legal winner thank year wave sausage worth useful legal winner thank yellow";

fn seed_holder() -> SensitiveBytes64 {
	let mut holder = SensitiveBytes64::zeroed();
	holder.as_mut_bytes().copy_from_slice(&SEED);
	holder
}

macro_rules! probes {
	($($module:ident),*) => {$(
		mod $module {
			use super::*;
			use qp_rusty_crystals_hdwallet::$module::{
				derive_key_from_mnemonic, derive_key_from_seed, Keypair, ADDRESS_INDEX,
			};

			fn path() -> String {
				format!("m/44'/189189'/0'/0'/{ADDRESS_INDEX}")
			}

			fn leaked(secret_key: &[u8], entropy: &[u8], f: impl FnOnce()) -> Vec<String> {
				let n = secret_key.len() / 4;
				let patterns = [
					("entropy", entropy),
					("SK.seed", &secret_key[..n]),
					("SK.prf", &secret_key[n..2 * n]),
				];
				probe_stack_for_named(STACK_BYTES, &patterns, f)
			}

			#[test]
			fn seed_derivation_leaves_no_secret() {
				let mut reference = Keypair::zeroed();
				derive_key_from_seed(&seed_holder(), &path(), &mut reference).unwrap();
				let secret_key = reference.secret().to_bytes();
				let mut xpriv = ExtendedPrivKey::zeroed();
				ExtendedPrivKey::derive(&SEED, &path(), &mut xpriv).unwrap();
				let entropy = *xpriv.secret().as_bytes();

				let planted = leaked(&secret_key[..], &entropy, || {
					let copy = (*secret_key, entropy);
					core::hint::black_box(&copy);
				});
				assert_eq!(planted.len(), 3);

				let found = leaked(&secret_key[..], &entropy, || {
					let seed = seed_holder();
					let mut keypair = Keypair::zeroed();
					derive_key_from_seed(&seed, &path(), &mut keypair).unwrap();
					core::hint::black_box(&keypair);
				});
				assert!(found.is_empty(), "left on the stack: {found:?}");
			}

			#[test]
			fn mnemonic_derivation_leaves_no_secret() {
				let mut reference = Keypair::zeroed();
				derive_key_from_mnemonic(MNEMONIC, None, &path(), &mut reference).unwrap();
				let secret_key = reference.secret().to_bytes();

				let found = leaked(&secret_key[..], &secret_key[..secret_key.len() / 4], || {
					let mut keypair = Keypair::zeroed();
					derive_key_from_mnemonic(MNEMONIC, None, &path(), &mut keypair).unwrap();
					core::hint::black_box(&keypair);
				});
				assert!(found.is_empty(), "left on the stack: {found:?}");
			}
		}
	)*};
}

probes!(slh_dsa_shake_128f, slh_dsa_sha2_256f);
