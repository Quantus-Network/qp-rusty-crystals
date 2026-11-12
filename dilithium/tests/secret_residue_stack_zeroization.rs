//! Regression tests (security review): decoding the secret key and the
//! arithmetic run on its polynomials must not leave secret-dependent values
//! in dead stack memory, in any representation.
//!
//! The other `*_stack_zeroization` probes search for byte windows of the
//! packed key, which a spilled copy of decoded coefficients does not match.
//! These run each operation twice on the same repainted stack with inputs
//! that differ only in s1, s2 and t0, so every stack byte that differs
//! afterwards is secret residue.
//!
//! Key generation and import produce public output that depends on
//! the secret, so they cannot be compared that way. For those the secret
//! vectors are recomputed and every run of their coefficients is searched for,
//! which also finds a copy the compiler spilled only in part.
//!
//! Only compiled for optimized builds (`cargo test --release`): the assertion
//! is about codegen.
#![cfg(not(debug_assertions))]

use core::hint::black_box;

use qp_rusty_crystals_dilithium::{packing, params, poly::Poly, polyvec, polyvec::Polyvec};
use qp_rusty_crystals_test_utils::{probe_stack_for_coefficients, stack_residue_diff};
use zeroize::Zeroize;

const STACK_BYTES: usize = 1024 * 1024;

fn load<const N: usize>(dst: &mut Polyvec<N>, src: &Polyvec<N>) {
	for (d, s) in dst.vec.iter_mut().zip(src.vec.iter()) {
		*d.coeffs_mut() = *s.coeffs();
	}
}

fn coefficients<const N: usize>(v: &Polyvec<N>) -> Vec<i32> {
	v.vec.iter().flat_map(|p| *p.coeffs()).collect()
}

fn ntt_of<const N: usize>(v: &Polyvec<N>) -> Polyvec<N> {
	let mut v_hat = v.clone();
	polyvec::ntt(&mut v_hat);
	v_hat
}

/// Asserts that `operation` leaves none of `secrets` on the stack, after
/// checking that the probe sees a planted copy of the last one.
fn assert_no_secret_vectors(
	secrets: &[(&'static str, Vec<i32>)],
	what: &str,
	operation: impl FnOnce(),
) {
	let vectors: Vec<(&str, &[i32])> =
		secrets.iter().map(|(name, v)| (*name, v.as_slice())).collect();
	let (name, planted) = vectors[vectors.len() - 1];
	assert_eq!(
		probe_stack_for_coefficients(STACK_BYTES, &vectors, || {
			let leaked: [i32; 8] = planted[..8].try_into().unwrap();
			black_box(&leaked);
		}),
		[name],
		"probe self-check: a deliberately leaked stack copy was not detected"
	);
	assert_eq!(
		probe_stack_for_coefficients(STACK_BYTES, &vectors, operation),
		[""; 0],
		"{what} left secret vectors in stack memory"
	);
}

macro_rules! secret_residue_tests {
	($mod_name:ident, $feature:literal) => {
		#[cfg(feature = $feature)]
		mod $mod_name {
			use super::*;
			use qp_rusty_crystals_dilithium::{
				params::$mod_name::{ETA, GAMMA2, K, L, SECRETKEYBYTES as SK},
				$mod_name::{Keypair, SecretKey},
			};

			struct Parts {
				rho: [u8; params::SEEDBYTES],
				tr: [u8; params::TR_BYTES],
				key: [u8; params::SEEDBYTES],
				t0: Polyvec<K>,
				s1: Polyvec<L>,
				s2: Polyvec<K>,
			}

			impl Parts {
				fn zeroed() -> Self {
					Self {
						rho: [0; params::SEEDBYTES],
						tr: [0; params::TR_BYTES],
						key: [0; params::SEEDBYTES],
						t0: Polyvec::default(),
						s1: Polyvec::default(),
						s2: Polyvec::default(),
					}
				}

				fn unpack(&mut self, sk: &[u8; SK]) -> bool {
					packing::unpack_sk::<K, L, ETA, SK>(
						&mut self.rho,
						&mut self.tr,
						&mut self.key,
						&mut self.t0,
						&mut self.s1,
						&mut self.s2,
						sk,
					)
				}

				fn pack(&self, sk: &mut [u8; SK]) {
					packing::pack_sk::<K, L, ETA, SK>(
						sk, &self.rho, &self.tr, &self.key, &self.t0, &self.s1, &self.s2,
					);
				}

				fn set_secret(&mut self, from: &Self) {
					load(&mut self.t0, &from.t0);
					load(&mut self.s1, &from.s1);
					load(&mut self.s2, &from.s2);
				}
			}

			fn unpack_and_drop(sk: &mut [u8; SK]) {
				let mut parts = Parts::zeroed();
				black_box(parts.unpack(sk));
				black_box(&parts);
				parts.key.zeroize();
			}

			const SEED: [u8; 32] = *b"secret-residue-stack-probe-seed!";

			fn unpacked(keypair: &Keypair) -> Parts {
				let mut parts = Parts::zeroed();
				assert!(parts.unpack(&keypair.secret().to_bytes()));
				parts
			}

			/// The secret vectors of a key: its polynomials and `t = A*s1 + s2`,
			/// whose low bits are `t0`.
			fn key_secrets(parts: &Parts) -> Vec<(&'static str, Vec<i32>)> {
				let s1_hat = ntt_of(&parts.s1);
				let mut t = Polyvec::<K>::default();
				polyvec::matrix_pointwise_montgomery_streamed(&mut t, &parts.rho, &s1_hat);
				polyvec::reduce(&mut t);
				polyvec::invntt_tomont(&mut t);
				polyvec::add(&mut t, &parts.s2);
				polyvec::caddq(&mut t);

				let (mut t1, mut t0) = (t.clone(), Polyvec::<K>::default());
				polyvec::power2round(&mut t1, &mut t0);
				assert_eq!(coefficients(&t0), coefficients(&parts.t0));

				vec![
					("s1", coefficients(&parts.s1)),
					("s2", coefficients(&parts.s2)),
					("t0", coefficients(&parts.t0)),
					("ntt(s1)", coefficients(&s1_hat)),
					("t", coefficients(&t)),
				]
			}

			#[test]
			fn key_generation_and_import_leave_no_secret_vectors_on_the_stack() {
				let mut seed = SEED;
				let keypair = Keypair::generate(&mut (&mut seed).into());
				let secrets = key_secrets(&unpacked(&keypair));

				let mut seed = SEED;
				let mut entropy = (&mut seed).into();
				assert_no_secret_vectors(&secrets, "key generation", || {
					let mut generated = Keypair::generate(&mut entropy);
					generated.zeroize();
				});

				let sk = keypair.secret().to_bytes();
				assert_no_secret_vectors(&secrets, "secret key import", || {
					let mut imported = SecretKey::from_bytes(sk.as_slice()).expect("valid key");
					imported.zeroize();
				});
			}

			#[test]
			fn secret_polynomial_operations_leave_no_residue_on_the_stack() {
				let parts: [Parts; 2] = [0x11u8, 0x77].map(|byte| {
					let mut seed: [u8; 32] =
						core::array::from_fn(|i| byte.wrapping_mul(i as u8 + 3) ^ 0x5c);
					unpacked(&Keypair::generate(&mut (&mut seed).into()))
				});

				// Two packed keys that differ only in s1, s2 and t0.
				let mut packed = [[0u8; SK]; 2];
				let mut current = Parts::zeroed();
				(current.rho, current.tr, current.key) = (parts[0].rho, parts[0].tr, parts[0].key);
				for (sk, secret) in packed.iter_mut().zip(&parts) {
					current.set_secret(secret);
					current.pack(sk);
				}

				let mut sk = [0u8; SK];
				assert_eq!(
					stack_residue_diff(
						STACK_BYTES,
						&mut sk,
						|sk, _| *sk = packed[0],
						unpack_and_drop
					),
					0,
					"probe self-check: identical inputs left different stacks"
				);
				assert!(
					stack_residue_diff(
						STACK_BYTES,
						&mut sk,
						|sk, run| *sk = packed[run],
						|sk| {
							let leaked: [u8; 32] = sk[SK - 32..].try_into().unwrap();
							black_box(&leaked);
						}
					) > 0,
					"probe self-check: a deliberately leaked stack copy was not detected"
				);

				assert_eq!(
					stack_residue_diff(
						STACK_BYTES,
						&mut sk,
						|sk, run| *sk = packed[run],
						unpack_and_drop
					),
					0,
					"unpack_sk left secret-dependent values in stack memory"
				);

				let mut challenge = Poly::default();
				for (i, c) in challenge.coeffs_mut().iter_mut().enumerate() {
					*c = (i as i32 * 7919) % params::Q;
				}
				let operations: [(&str, &dyn Fn(&mut Parts)); 7] = [
					("pack_sk", &|p| {
						let mut sk = [0u8; SK];
						p.pack(&mut sk);
						black_box(&sk);
						sk.zeroize();
					}),
					("ntt and invntt_tomont", &|p| {
						let mut v = Polyvec::<L>::default();
						load(&mut v, &p.s1);
						polyvec::ntt(&mut v);
						black_box(&v);
						polyvec::invntt_tomont(&mut v);
						black_box(&v);
					}),
					("reduce and caddq", &|p| {
						let mut v = Polyvec::<K>::default();
						load(&mut v, &p.t0);
						polyvec::reduce(&mut v);
						polyvec::caddq(&mut v);
						black_box(&v);
					}),
					("power2round", &|p| {
						let mut v = Polyvec::<K>::default();
						let mut v0 = Polyvec::<K>::default();
						load(&mut v, &p.t0);
						polyvec::caddq(&mut v);
						polyvec::power2round(&mut v, &mut v0);
						black_box((&v, &v0));
					}),
					("decompose and make_hint", &|p| {
						let mut v = Polyvec::<K>::default();
						let mut v0 = Polyvec::<K>::default();
						let mut hint = Polyvec::<K>::default();
						load(&mut v, &p.t0);
						polyvec::caddq(&mut v);
						polyvec::decompose::<K, GAMMA2>(&mut v, &mut v0);
						let weight = polyvec::make_hint::<K, GAMMA2>(&mut hint, &v0, &v);
						black_box((&v, &v0, &hint, weight));
					}),
					("is_norm_within_bound", &|p| {
						black_box(polyvec::is_norm_within_bound(&p.s1, 1 << 17));
					}),
					("pointwise multiplication", &|p| {
						let mut product = Polyvec::<L>::default();
						polyvec::pointwise_poly_montgomery(&mut product, &challenge, &p.s1);
						let mut sum = Poly::default();
						polyvec::pointwise_acc_montgomery(&mut sum, &product, &p.s1);
						black_box((&product, &sum));
					}),
				];
				for (name, operation) in operations {
					assert_eq!(
						stack_residue_diff(
							STACK_BYTES,
							&mut current,
							|current, run| current.set_secret(&parts[run]),
							operation,
						),
						0,
						"{name} left secret-dependent values in stack memory"
					);
				}
			}
		}
	};
}

secret_residue_tests!(ml_dsa_44, "ml-dsa-44");
secret_residue_tests!(ml_dsa_65, "ml-dsa-65");
secret_residue_tests!(ml_dsa_87, "ml-dsa-87");
