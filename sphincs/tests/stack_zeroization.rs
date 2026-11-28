//! Key generation and signing must leave no copy of `SK.seed` or `SK.prf` in
//! dead stack memory. The property depends on codegen, so the probes only
//! run in optimized builds.
#![cfg(not(debug_assertions))]

use qp_rusty_crystals_test_utils::probe_stack_for_named;

const STACK_BYTES: usize = 1024 * 1024;

macro_rules! probes {
	($($module:ident),*) => {$(
		mod $module {
			use super::*;
			use qp_rusty_crystals_sphincs::$module::{Keypair, N, SEEDBYTES};

			const SEED: [u8; SEEDBYTES] = {
				let mut seed = [0u8; SEEDBYTES];
				let mut i = 0;
				while i < SEEDBYTES {
					seed[i] = (i as u8).wrapping_mul(37).wrapping_add(11);
					i += 1;
				}
				seed
			};

			fn leaked(f: impl FnOnce()) -> Vec<String> {
				let patterns = [("SK.seed", &SEED[..N]), ("SK.prf", &SEED[N..2 * N])];
				probe_stack_for_named(STACK_BYTES, &patterns, f)
			}

			#[test]
			fn probe_detects_a_planted_copy() {
				let found = leaked(|| {
					let planted = SEED;
					core::hint::black_box(&planted);
				});
				assert_eq!(found.len(), 2);
			}

			#[test]
			fn keygen_and_sign_leave_no_secret() {
				let found = leaked(|| {
					let mut seed = core::hint::black_box(SEED);
					let keypair = Keypair::generate(&mut seed);
					let deterministic = keypair.sign(b"probe", None, None).unwrap();
					let hedged = keypair.sign(b"probe", Some(b"ctx"), Some(&[5; N])).unwrap();
					core::hint::black_box((&keypair, &deterministic, &hedged));
				});
				assert!(found.is_empty(), "left on the stack: {found:?}");
			}
		}
	)*};
}

probes!(slh_dsa_sha2_128f, slh_dsa_shake_128f, slh_dsa_sha2_256f, slh_dsa_shake_256f);
