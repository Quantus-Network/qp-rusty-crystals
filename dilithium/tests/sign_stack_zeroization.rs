//! Regression tests (security review): signing and key generation must not
//! leave secret material in dead stack memory.
//!
//! The signing path copies the packed key's secret fields into stack locals:
//! the signing key `K` (absorbed to derive the mask seed ρ'), ρ' itself, and
//! the unpacked `s1`/`s2`/`t0` polynomials. All of them carry explicit
//! `.zeroize()` calls (and `SigningContext` zeroizes on drop), but nothing
//! verified that discipline survives optimized codegen. Leaking ρ' or the
//! mask `y` is equivalent to leaking the key (the published response is
//! `z = y + c*s1`); leaking `K` breaks the deterministic-signing hedge. Key
//! generation likewise wipes its packed-key locals, verified here from the
//! outside for the first time.
//!
//! Detection uses the same painted-stack technique as the crate's
//! `import_stack_zeroization` test: run the operation on a dedicated
//! sentinel-painted buffer via `psm::on_stack`, then scan the buffer — which
//! we own, so the read is sound — for distinctive 32-byte windows of the
//! secret key. Scanned windows:
//!
//! - `K` at offset 64..96 of the packed key (rho || key || tr || s1 ...): high-entropy XOF output
//!   that the signing path must copy to derive ρ'.
//! - the packed-s1 window at 128..160: signing unpacks the key through a reference, so this window
//!   appearing on the stack would mean a full packed-key copy was smeared and dropped unwiped.
//! - the keygen input seed, which deterministically derives the entire key.
//!
//! Key generation is seed-deterministic, so the reference keypair generated
//! outside the probe and the probed generation produce identical keys,
//! letting the same patterns serve both scenarios. Scenario closures capture
//! only references, so the probe machinery cannot plant a match itself.
//!
//! The assertion is about codegen and is per-monomorphization, so the suite
//! is stamped once per enabled ML-DSA variant. Only compiled for optimized
//! builds (`cargo test --release`): unoptimized codegen materializes
//! compiler-generated move temporaries for the large by-value key structs
//! which no source-level fix can wipe.
#![cfg(not(debug_assertions))]

use qp_rusty_crystals_test_utils::probe_stack_for;

// 4 MiB: comfortably above the keygen/signing frames (matrix expansion,
// NTT chains, rejection-sampling loops).
const STACK_BYTES: usize = 4 * 1024 * 1024;

/// A 32-byte window of the packed secret key. SK layout (identical prefix for
/// every parameter set): rho (32) || key (32) || tr (64) || s1 || s2 || t0.
fn sk_window(sk_bytes: &[u8], offset: usize) -> [u8; 32] {
	let mut pattern = [0u8; 32];
	pattern.copy_from_slice(&sk_bytes[offset..offset + 32]);
	pattern
}

macro_rules! sign_stack_zeroization_tests {
	($mod_name:ident, $feature:literal) => {
		#[cfg(feature = $feature)]
		mod $mod_name {
			use super::{probe_stack_for, sk_window};
			use qp_rusty_crystals_dilithium::$mod_name::Keypair;
			use zeroize::Zeroize;

			/// Distinctive seed; a repeated single byte could false-positive
			/// against unrelated memory noise.
			const SEED: [u8; 32] = *b"sign-stack-zeroize-seed-pattern!";

			#[test]
			fn signing_and_keygen_leave_no_secret_copies_on_the_stack() {
				let mut seed = SEED;
				let keypair = Keypair::generate(&mut (&mut seed).into());
				let sk_bytes = keypair.secret().to_bytes();
				let k_pattern = sk_window(sk_bytes.as_slice(), 32);
				let s1_pattern = sk_window(sk_bytes.as_slice(), 128);
				let message = b"stack zeroization probe";

				// Sanity: the technique detects an unwiped copy. A closure
				// that deliberately leaves K in a dead stack frame must be
				// seen.
				assert!(
					probe_stack_for(super::STACK_BYTES, &k_pattern, || {
						let leaked: [u8; 32] = k_pattern;
						core::hint::black_box(&leaked);
					}),
					"probe self-check: a deliberately leaked stack copy was not detected"
				);

				// Scenario A: signing must wipe its copy of the signing key K
				// (copied out of the packed key to derive the mask seed rho').
				let sign_leaked_k = probe_stack_for(super::STACK_BYTES, &k_pattern, || {
					let sig = keypair.sign(message, None, None).expect("signing succeeds");
					core::hint::black_box(&sig);
				});

				// Scenario B: signing reads the packed key through a
				// reference; no full packed-key copy may be smeared onto the
				// stack and dropped unwiped.
				let sign_leaked_s1 = probe_stack_for(super::STACK_BYTES, &s1_pattern, || {
					let sig = keypair.sign(message, None, None).expect("signing succeeds");
					core::hint::black_box(&sig);
				});

				// Scenario B2 (security review): *hedged* signing must not
				// leave the caller's hedge randomness `rnd` in stack memory.
				// ρ' = H(K || rnd || μ), so an attacker who recovers rnd from
				// dead stack memory and also obtains K can reconstruct the
				// mask seed and mount the known-mask attack on z = y + c*s1 —
				// defeating exactly the K-compromise protection hedging is
				// for. The wrapper is built outside the probe (like the
				// keygen seed holders) so the closure captures only
				// references and cannot plant a match itself. Distinctive
				// pattern for the same reason as SEED.
				let hedge_pattern: [u8; 32] = *b"hedge-randomness-stack-pattern!!";
				let mut hedge_raw = hedge_pattern;
				let hedge = qp_rusty_crystals_dilithium::SensitiveBytes32::new(&mut hedge_raw);
				let sign_leaked_hedge = probe_stack_for(super::STACK_BYTES, &hedge_pattern, || {
					let sig = keypair.sign(message, None, Some(&hedge)).expect("signing succeeds");
					core::hint::black_box(&sig);
				});

				// Scenario C: key generation. Same seed => identical key, so
				// the reference patterns apply. The seed holder is built
				// outside the probe (the closure captures only a reference),
				// and the produced keypair is wiped in place.
				let mut seed_again = SEED;
				let mut sensitive = (&mut seed_again).into();
				let keygen_closure = || {
					let mut generated = Keypair::generate(&mut sensitive);
					generated.zeroize();
				};
				let keygen_leaked_k =
					probe_stack_for(super::STACK_BYTES, &k_pattern, keygen_closure);

				// Scenario D/E: keygen must not leave the packed-s1 window or
				// the raw input seed behind either. Fresh runs per pattern
				// (each needs its own seed holder; generate consumes it).
				let mut seed_third = SEED;
				let mut sensitive_third = (&mut seed_third).into();
				let keygen_leaked_s1 = probe_stack_for(super::STACK_BYTES, &s1_pattern, || {
					let mut generated = Keypair::generate(&mut sensitive_third);
					generated.zeroize();
				});
				let mut seed_fourth = SEED;
				let mut sensitive_fourth = (&mut seed_fourth).into();
				let keygen_leaked_seed = probe_stack_for(super::STACK_BYTES, &SEED, || {
					let mut generated = Keypair::generate(&mut sensitive_fourth);
					generated.zeroize();
				});

				assert!(!sign_leaked_k, "signing left the signing key K in stack memory");
				assert!(!sign_leaked_s1, "signing left a packed secret-key copy in stack memory");
				assert!(
					!sign_leaked_hedge,
					"hedged signing left the hedge randomness rnd in stack memory"
				);
				assert!(!keygen_leaked_k, "key generation left the signing key K in stack memory");
				assert!(
					!keygen_leaked_s1,
					"key generation left a packed secret-key copy in stack memory"
				);
				assert!(
					!keygen_leaked_seed,
					"key generation left the raw input seed in stack memory"
				);
			}
		}
	};
}

sign_stack_zeroization_tests!(ml_dsa_44, "ml-dsa-44");
sign_stack_zeroization_tests!(ml_dsa_65, "ml-dsa-65");
sign_stack_zeroization_tests!(ml_dsa_87, "ml-dsa-87");
