//! Shared public-API surface for every ML-DSA parameter set.
//!
//! The [`define_ml_dsa`] macro expands to the concrete `Keypair` / `SecretKey` /
//! `PublicKey` types for one variant, wiring them to [`crate::sign`]'s
//! const-generic cores. Each of [`crate::ml_dsa_44`], [`crate::ml_dsa_65`], and
//! [`crate::ml_dsa_87`] is a one-line instantiation of this macro (plus any
//! variant-specific tests). Expanding the macro yields the same code that
//! previously lived only in `ml_dsa_87.rs`.

/// Build the FIPS 204 "pure" ML-DSA domain-separator prefix
/// `[0, |ctx|, ctx…]` into `buf`, returning the prefix length. An absent
/// context encodes as `[0, 0]`; a context longer than 255 bytes is invalid
/// and returns `None`. The prefix bytes are parameter-set independent, so
/// this lives outside [`define_ml_dsa!`] and is shared by every variant's
/// sign and verify paths.
pub(crate) fn ctx_prefix(ctx: Option<&[u8]>, buf: &mut [u8; 2 + 255]) -> Option<usize> {
	buf[0] = 0; // FIPS 204 "pure" domain byte; don't rely on the caller zeroing the buffer
	buf[1] = 0;
	match ctx {
		Some(x) if x.len() > 255 => None,
		Some(x) => {
			buf[1] = x.len() as u8;
			buf[2..2 + x.len()].copy_from_slice(x);
			Some(2 + x.len())
		},
		None => Some(2),
	}
}

/// Define the public ML-DSA API for one parameter-set module.
///
/// `$params` must be a path to a module exposing the FIPS 204 constants
/// (`K`, `L`, `ETA`, `TAU`, `GAMMA1`, `GAMMA2`, `OMEGA`, `C_DASH_BYTES`,
/// `POLYZ_PACKEDBYTES`, `POLYW1_PACKEDBYTES`, `PUBLICKEYBYTES`,
/// `SECRETKEYBYTES`, `SIGNBYTES`) — i.e. one of [`crate::params::ml_dsa_44`],
/// [`crate::params::ml_dsa_65`], or [`crate::params::ml_dsa_87`].
macro_rules! define_ml_dsa {
	($params:path) => {
		use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

		use core::fmt;
		use $crate::{
			errors::{KeyParsingError, KeyParsingError::BadSecretKey, SignatureError},
			params::SEEDBYTES,
			polyvec::Polyvec,
			SensitiveBytes32,
		};

		use $params::{
			C_DASH_BYTES, ETA, GAMMA1, GAMMA2, K, L, OMEGA, POLYW1_PACKEDBYTES, POLYZ_PACKEDBYTES,
			PUBLICKEYBYTES as PK_BYTES, SECRETKEYBYTES as SK_BYTES, SIGNBYTES as SIG_BYTES, TAU,
		};

		pub const SECRETKEYBYTES: usize = SK_BYTES;
		pub const PUBLICKEYBYTES: usize = PK_BYTES;
		pub const SIGNBYTES: usize = SIG_BYTES;
		pub const KEYPAIRBYTES: usize = SECRETKEYBYTES + PUBLICKEYBYTES;

		/// Maximum message size for signing/verification (64 MiB).
		///
		/// This limit prevents denial-of-service attacks via memory exhaustion from
		/// oversized messages. The limit is generous enough for any legitimate use case.
		pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024;

		pub type Signature = [u8; SIGNBYTES];

		/// A pair of private and public keys.
		///
		/// `Clone` is intentionally not derived because the embedded `SecretKey` is sensitive.
		/// To explicitly copy a keypair (e.g. to move it into a closure), serialize and
		/// reconstruct: `Keypair::from_bytes(keypair.to_bytes().as_slice())?`. This forces
		/// the duplication of secret material to be visible at every call site.
		///
		/// # Invariant
		///
		/// The public half always corresponds to the secret half. Every constructor
		/// enforces it — [`Keypair::generate`] by construction, [`Keypair::from_bytes`]
		/// and [`Keypair::from_parts`] by re-deriving the public key from the secret —
		/// and the fields are private, so the halves cannot be assembled or swapped
		/// independently. [`sign`](Self::sign) and [`verify`](Self::verify) delegate
		/// to the respective halves, and [`to_bytes`](Self::to_bytes) serializes them
		/// directly; all three rely on this invariant. A mismatched keypair does not
		/// compile (illustrated with `ml_dsa_87`; the same privacy holds on every
		/// parameter-set module):
		///
		/// ```compile_fail
		/// use qp_rusty_crystals_dilithium::ml_dsa_87::{Keypair, PublicKey, SecretKey};
		///
		/// fn forge(secret: SecretKey, public: PublicKey) -> Keypair {
		///     Keypair { secret, public } // ERROR: fields are private
		/// }
		/// ```
		///
		/// ```compile_fail
		/// use qp_rusty_crystals_dilithium::ml_dsa_87::{Keypair, PublicKey};
		///
		/// fn swap_public(kp: &mut Keypair, other: PublicKey) {
		///     kp.public = other; // ERROR: field is private
		/// }
		/// ```
		pub struct Keypair {
			secret: SecretKey,
			public: PublicKey,
		}

		impl Keypair {
			/// Generate a Keypair instance.
			///
			/// # Arguments
			///
			/// * 'entropy' - bytes for determining the generation process (must be at least 32
			///   bytes)
			///
			/// The entropy is borrowed mutably and zeroized in place after use
			/// (security review): taking it by value would move — i.e. copy —
			/// it through parameter slots that are dead but never dropped, so
			/// `ZeroizeOnDrop` could not wipe them. The caller's value is
			/// consumed in the practical sense: it is all zeros afterwards.
			pub fn generate(entropy: &mut SensitiveBytes32) -> Keypair {
				let mut pk = [0u8; PUBLICKEYBYTES];
				// The packed secret key lives in a self-wiping buffer, and the
				// Keypair is built in tail position rather than through a named
				// local that is returned afterwards (security review): binding
				// the struct first and returning it later moves it out of this
				// frame, and the dead source copy of the full packed key is
				// beyond the reach of any zeroize call (the release-mode
				// `sign_stack_zeroization` probe found two such copies). The
				// same tail-construction shape keeps `from_bytes` clean under
				// the `import_stack_zeroization` probes.
				let mut sk = Zeroizing::new([0u8; SECRETKEYBYTES]);
				$crate::sign::keypair_var::<K, L, ETA, PUBLICKEYBYTES, SECRETKEYBYTES>(
					&mut pk, &mut sk, entropy,
				);
				entropy.as_mut_bytes().zeroize();
				let public = PublicKey::from_bytes(&pk).expect("Should never fail");
				// Constructed directly rather than via `SecretKey::from_bytes`:
				// a freshly generated key is consistent by construction, and the
				// import-path validation would redo the keygen-scale derivation.
				Keypair { secret: SecretKey { bytes: *sk }, public }
			}

			/// The secret half.
			pub fn secret(&self) -> &SecretKey {
				&self.secret
			}

			/// The public half.
			pub fn public(&self) -> &PublicKey {
				&self.public
			}

			/// The correspondence check shared by [`Keypair::from_parts`] and
			/// [`Keypair::from_bytes`]: re-derive the public key from the
			/// secret bytes (a keygen-scale computation that also validates
			/// the packed secret-key invariants) and compare it to `public`.
			///
			/// Borrow-only on purpose: taking the secret by value would move
			/// it through this frame and leave a dead stack copy that no drop
			/// can wipe (a regression the release-mode
			/// `import_stack_zeroization` probes catch). Callers keep the
			/// bytes wherever they already are and control their cleanup.
			fn check_correspondence(
				secret_bytes: &[u8; SECRETKEYBYTES],
				public: &PublicKey,
			) -> Result<(), KeyParsingError> {
				let derived_public = $crate::sign::public_key_from_secret_var::<
					K,
					L,
					ETA,
					PUBLICKEYBYTES,
					SECRETKEYBYTES,
				>(secret_bytes)
				.ok_or(KeyParsingError::BadKeypair)?;
				if derived_public != public.bytes {
					return Err(KeyParsingError::BadKeypair);
				}
				Ok(())
			}

			/// Assemble a keypair from an already-imported secret and public key.
			///
			/// Enforces the same correspondence invariant as [`Keypair::from_bytes`]:
			/// the public key is re-derived from the secret half (a keygen-scale
			/// computation) and must match `public` exactly, otherwise
			/// [`KeyParsingError::BadKeypair`] is returned and the secret is wiped by
			/// its own drop. This is the only way to build a `Keypair` from parts —
			/// the fields are private precisely so a mismatched pair (signing under
			/// one key while advertising another) is unrepresentable.
			pub fn from_parts(
				secret: SecretKey,
				public: PublicKey,
			) -> Result<Keypair, KeyParsingError> {
				Self::check_correspondence(&secret.bytes, &public)?;
				Ok(Keypair { secret, public })
			}

			/// Convert a Keypair to a bytes array.
			///
			/// Returns a self-wiping buffer containing private and public key bytes.
			/// The buffer contains the full secret key, so it is `Zeroizing`: it is
			/// erased when dropped, and callers no longer need (or are able to
			/// forget) manual cleanup. Deref to `[u8; KEYPAIRBYTES]` for access.
			pub fn to_bytes(&self) -> Zeroizing<[u8; KEYPAIRBYTES]> {
				let mut result = Zeroizing::new([0u8; KEYPAIRBYTES]);
				result[..SECRETKEYBYTES].copy_from_slice(&self.secret.bytes);
				result[SECRETKEYBYTES..].copy_from_slice(&self.public.to_bytes());
				Zeroizing::new(*result)
			}

			/// Create a Keypair from bytes.
			///
			/// # Consistency check
			///
			/// The public half is re-derived from the secret half and must match the
			/// supplied public-key bytes exactly; otherwise this returns
			/// [`KeyParsingError::BadKeypair`]. The secret key's internal invariants
			/// (stored `t0` and `tr`) are checked as well; see
			/// [`SecretKey::from_bytes`].
			///
			/// The fields are private and [`Keypair::from_parts`] performs the same
			/// correspondence check, so the invariant established here holds for the
			/// lifetime of every `Keypair` value.
			///
			/// One packed field is *not* (and cannot be) validated: the nonce seed
			/// `K`, which is independent entropy with no stored commitment. A blob
			/// whose `K` was tampered imports cleanly and signs verifiably, but
			/// known-K **deterministic** signatures leak the secret key. Store key
			/// blobs with integrity protection, or pass fresh `hedge` randomness to
			/// [`sign`](Self::sign) when storage integrity cannot be guaranteed.
			///
			/// # Cost / DoS note
			///
			/// Confirming secret/public correspondence is inherently a keygen-scale
			/// computation (re-deriving the public key from the secret). A cheap
			/// structural pre-check rejects the common garbage case — a blob with
			/// out-of-range packed coefficients — before that work runs, but a blob
			/// crafted with canonical coefficients and an inconsistent public key
			/// still costs one full derivation to reject. Callers exposing this
			/// import to untrusted or unauthenticated input should rate-limit or
			/// authenticate before calling it.
			pub fn from_bytes(bytes: &[u8]) -> Result<Keypair, KeyParsingError> {
				if bytes.len() != KEYPAIRBYTES {
					return Err(KeyParsingError::BadKeypair);
				}
				let (secret_slice, public_bytes) = bytes.split_at(SECRETKEYBYTES);
				let mut secret_bytes = Zeroizing::new([0u8; SECRETKEYBYTES]);
				secret_bytes.copy_from_slice(secret_slice);
				let public =
					PublicKey::from_bytes(public_bytes).map_err(|_| KeyParsingError::BadKeypair)?;

				// Validate by borrowing the self-wiping buffer, then construct
				// the Keypair directly. Building a `SecretKey` first and
				// passing it to `from_parts` by value would move the array
				// through an extra stack frame and leave a dead plaintext
				// copy behind (caught by the release-mode
				// `import_stack_zeroization` probes). Going through
				// `SecretKey::from_bytes` instead would redo the keygen-scale
				// derivation that `check_correspondence` already performs.
				Self::check_correspondence(&secret_bytes, &public)?;
				Ok(Keypair { secret: SecretKey { bytes: *secret_bytes }, public })
			}

			/// Compute a signature for a given message.
			///
			/// # Arguments
			///
			/// * 'msg' - message to sign (max 64 MiB)
			/// * 'ctx' - optional context string (max 255 bytes)
			/// * 'hedge' - optional random bytes for hedged signing. `None` selects deterministic
			///   mode (`ρ' = H(K || 0 || μ)`), whose masks are a pure function of the stored nonce
			///   seed `K` and the message — prefer `Some(fresh randomness)` unless
			///   byte-reproducible signatures are required, especially when key-blob storage
			///   integrity cannot be guaranteed (see [`SecretKey::from_bytes`] on the unvalidatable
			///   `K`).
			///
			/// The hedge is taken as a borrowed `SensitiveBytes32` rather than bare
			/// bytes (security review): building the wrapper (via `SensitiveBytes32::new`)
			/// wipes the caller's raw buffer, the wrapper zeroizes itself on drop, and
			/// signing only ever *borrows* the bytes — so no unwiped `Copy` of `rnd` is
			/// smeared through parameter slots on the call chain. A recovered `rnd` plus
			/// a compromised `K` reconstructs ρ' and enables the known-mask attack
			/// hedging is meant to prevent.
			pub fn sign(
				&self,
				msg: &[u8],
				ctx: Option<&[u8]>,
				hedge: Option<&$crate::SensitiveBytes32>,
			) -> Result<Signature, SignatureError> {
				self.secret.sign(msg, ctx, hedge)
			}

			/// Verify a signature for a given message with a public key.
			pub fn verify(&self, msg: &[u8], sig: &[u8], ctx: Option<&[u8]>) -> bool {
				self.public.verify(msg, sig, ctx)
			}
		}

		impl fmt::Debug for Keypair {
			fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				f.debug_struct("Keypair").field("public", &self.public).finish()
			}
		}

		/// Wipes the secret half in place (the public half is public data and is
		/// left intact). With the fields private, this is the supported way for
		/// callers to erase an imported keypair's secret material on demand; the
		/// same wipe runs automatically when the `Keypair` drops.
		impl Zeroize for Keypair {
			fn zeroize(&mut self) {
				self.secret.zeroize();
			}
		}

		/// Private key.
		///
		/// `Clone` is intentionally not derived because the underlying bytes are sensitive.
		/// To explicitly copy a secret key, use `SecretKey::from_bytes(&sk.to_bytes())?`,
		/// which makes the duplication of secret material visible at every call site.
		///
		/// `Zeroize` is derived (in addition to `ZeroizeOnDrop`) so wrapper types that
		/// embed a `SecretKey` can themselves `#[derive(Zeroize, ZeroizeOnDrop)]`.
		#[derive(Zeroize, ZeroizeOnDrop)]
		pub struct SecretKey {
			bytes: [u8; SECRETKEYBYTES],
		}

		impl SecretKey {
			/// Returns a copy of the underlying bytes in a self-wiping buffer.
			pub fn to_bytes(&self) -> Zeroizing<[u8; SECRETKEYBYTES]> {
				Zeroizing::new(self.bytes)
			}

			/// Create a SecretKey from bytes, validating packed-key invariants
			/// (stored `t0` must match the low bits re-derived from `(rho, s1, s2)`,
			/// stored `tr` must equal `SHAKE256(pk)`, and secret coefficients must
			/// lie in `[-ETA, ETA]`).
			///
			/// The nonce seed `K` is *not* (and cannot be) validated: it is
			/// independent entropy with no stored commitment. A blob whose `K` was
			/// tampered imports cleanly and signs verifiably, but known-K
			/// **deterministic** signatures leak the secret key. Store key blobs
			/// with integrity protection, or pass fresh `hedge` randomness to
			/// [`sign`](Self::sign) when storage integrity cannot be guaranteed.
			///
			/// # Cost / DoS note
			///
			/// Validating a secret key re-derives its public key, a keygen-scale
			/// computation. A cheap structural pre-check rejects the common garbage
			/// case — a blob with out-of-range packed coefficients — before that
			/// work runs, but a blob crafted with canonical coefficients and an
			/// inconsistent stored `t0`/`tr` still costs one full derivation to
			/// reject. Callers exposing this import to untrusted or unauthenticated
			/// input should rate-limit or authenticate before calling it.
			pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, KeyParsingError> {
				if bytes.len() != SECRETKEYBYTES {
					return Err(BadSecretKey);
				}
				let mut sk = Zeroizing::new([0u8; SECRETKEYBYTES]);
				sk.copy_from_slice(bytes);
				let pk_ok = $crate::sign::public_key_from_secret_var::<
					K,
					L,
					ETA,
					PUBLICKEYBYTES,
					SECRETKEYBYTES,
				>(&sk);
				pk_ok.ok_or(BadSecretKey)?;
				Ok(SecretKey { bytes: *sk })
			}

			/// Compute a signature for a given message.
			///
			/// See [`Keypair::sign`] for the argument contract, in particular the
			/// deterministic-vs-hedged trade-off of `hedge` and why it is passed
			/// as a borrowed self-wiping wrapper.
			pub fn sign(
				&self,
				msg: &[u8],
				ctx: Option<&[u8]>,
				hedge: Option<&$crate::SensitiveBytes32>,
			) -> Result<Signature, SignatureError> {
				if msg.len() > MAX_MESSAGE_SIZE {
					return Err(SignatureError::MessageTooLong);
				}
				let mut prefix = [0u8; 2 + 255];
				let prefix_len = $crate::frontend::ctx_prefix(ctx, &mut prefix)
					.ok_or(SignatureError::ContextTooLong)?;
				let mut sig: Signature = [0u8; SIGNBYTES];
				$crate::sign::signature_var::<
					K,
					L,
					ETA,
					TAU,
					GAMMA1,
					GAMMA2,
					OMEGA,
					C_DASH_BYTES,
					POLYZ_PACKEDBYTES,
					POLYW1_PACKEDBYTES,
					{ K * POLYW1_PACKEDBYTES },
					PUBLICKEYBYTES,
					SECRETKEYBYTES,
					SIGNBYTES,
				>(&mut sig, &prefix[..prefix_len], msg, &self.bytes, hedge);
				Ok(sig)
			}
		}

		#[derive(Eq, Clone, PartialEq, Debug, Hash, PartialOrd, Ord)]
		pub struct PublicKey {
			pub bytes: [u8; PUBLICKEYBYTES],
		}

		impl PublicKey {
			/// Returns a copy of underlying bytes.
			pub fn to_bytes(&self) -> [u8; PUBLICKEYBYTES] {
				self.bytes
			}

			/// Create a PublicKey from bytes.
			pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, KeyParsingError> {
				let bytes: [u8; PUBLICKEYBYTES] =
					bytes.try_into().map_err(|_| KeyParsingError::BadPublicKey)?;

				// Reject the degenerate all-zero t1 public key.
				let mut rho = [0u8; SEEDBYTES];
				let mut t1 = Polyvec::<K>::default();
				$crate::packing::unpack_pk(&mut rho, &mut t1, &bytes);
				if t1.vec.iter().all(|p| p.coeffs.iter().all(|&c| c == 0)) {
					return Err(KeyParsingError::BadPublicKey);
				}

				Ok(PublicKey { bytes })
			}

			/// Verify a signature for a given message with a public key.
			pub fn verify(&self, msg: &[u8], sig: &[u8], ctx: Option<&[u8]>) -> bool {
				let sig: &[u8; SIGNBYTES] = match sig.try_into() {
					Ok(s) => s,
					Err(_) => return false,
				};
				if msg.len() > MAX_MESSAGE_SIZE {
					return false;
				}
				let mut prefix = [0u8; 2 + 255];
				let Some(prefix_len) = $crate::frontend::ctx_prefix(ctx, &mut prefix) else {
					return false;
				};
				$crate::sign::verify_var::<
					K,
					L,
					ETA,
					TAU,
					GAMMA1,
					GAMMA2,
					OMEGA,
					C_DASH_BYTES,
					POLYZ_PACKEDBYTES,
					POLYW1_PACKEDBYTES,
					{ K * POLYW1_PACKEDBYTES },
					PUBLICKEYBYTES,
					SECRETKEYBYTES,
					SIGNBYTES,
				>(sig, &prefix[..prefix_len], msg, &self.bytes)
			}
		}
	};
}

pub(crate) use define_ml_dsa;

/// Basic per-variant smoke tests (sign/verify round trip with the FIPS 204
/// Table 2 sizes pinned, hedged + context behavior, oversized-message
/// rejection), stamped into a parameter-set module's `mod tests` via
/// `crate::frontend::basic_variant_tests!(SIGNBYTES, PUBLICKEYBYTES,
/// SECRETKEYBYTES);`. The bodies were previously duplicated byte-for-byte in
/// `ml_dsa_44.rs` and `ml_dsa_65.rs`, differing only in the pinned sizes.
#[cfg(test)]
macro_rules! basic_variant_tests {
	($sig_bytes:expr, $pk_bytes:expr, $sk_bytes:expr) => {
		fn basic_test_entropy() -> $crate::SensitiveBytes32 {
			use rand::RngExt;
			let mut rng = rand::rng();
			let mut bytes = [0u8; 32];
			rng.fill(&mut bytes);
			(&mut bytes).into()
		}

		#[test]
		fn self_verify_roundtrip() {
			use super::{Keypair, PUBLICKEYBYTES, SECRETKEYBYTES, SIGNBYTES};

			let keys = Keypair::generate(&mut basic_test_entropy());
			let msg = b"variant smoke test";
			let sig = keys.sign(msg, None, None).unwrap();
			assert!(keys.verify(msg, &sig, None));
			assert_eq!(sig.len(), SIGNBYTES);
			assert_eq!(SIGNBYTES, $sig_bytes);
			assert_eq!(PUBLICKEYBYTES, $pk_bytes);
			assert_eq!(SECRETKEYBYTES, $sk_bytes);
		}

		#[test]
		fn hedged_and_context() {
			use super::Keypair;

			let keys = Keypair::generate(&mut basic_test_entropy());
			let msg = b"ctx";
			let h1 = basic_test_entropy();
			let h2 = basic_test_entropy();
			let s1 = keys.sign(msg, Some(b"a"), Some(&h1)).unwrap();
			let s2 = keys.sign(msg, Some(b"a"), Some(&h2)).unwrap();
			assert_ne!(s1, s2);
			assert!(keys.verify(msg, &s1, Some(b"a")));
			assert!(!keys.verify(msg, &s1, Some(b"b")));
		}

		#[test]
		fn rejects_oversized_message() {
			use super::{Keypair, MAX_MESSAGE_SIZE, SIGNBYTES};
			use $crate::errors::SignatureError;

			let keys = Keypair::generate(&mut basic_test_entropy());
			let big = alloc::vec![0u8; MAX_MESSAGE_SIZE + 1];
			assert!(matches!(keys.sign(&big, None, None), Err(SignatureError::MessageTooLong)));
			assert!(!keys.verify(&big, &[0u8; SIGNBYTES], None));
		}
	};
}

#[cfg(test)]
pub(crate) use basic_variant_tests;

/// Adversarial key-import regression tests, stamped into each parameter-set
/// module's `mod tests` via `crate::frontend::adversarial_import_tests!();`.
///
/// The validated import paths (`Keypair::from_bytes`, `SecretKey::from_bytes`,
/// `PublicKey::from_bytes`, `Keypair::from_parts`) are monomorphized per
/// parameter set, and some of the defenses are parameter-dependent — most
/// notably the canonical range of packed secret coefficients differs between
/// `ETA = 2` (44/87, 3-bit slots) and `ETA = 4` (65, 4-bit slots). Stamping
/// the suite per variant binds every monomorphization, not just ML-DSA-87.
///
/// Must be invoked inside the `mod tests` of a module generated by
/// [`define_ml_dsa!`], so `super::` resolves to that variant's frontend.
#[cfg(test)]
macro_rules! adversarial_import_tests {
	() => {
		fn adversarial_entropy() -> $crate::SensitiveBytes32 {
			use rand::RngExt;
			let mut rng = rand::rng();
			let mut bytes = [0u8; 32];
			rng.fill(&mut bytes);
			(&mut bytes).into()
		}

		// A keypair blob whose public half does not correspond to its secret
		// half must be rejected. Otherwise an imported keypair could sign with
		// one key while advertising an unrelated public key (e.g. an
		// unspendable receive address).
		#[test]
		fn from_bytes_rejects_mismatched_public_key() {
			use super::{Keypair, KEYPAIRBYTES, SECRETKEYBYTES};
			use $crate::errors::KeyParsingError;

			let keys_a = Keypair::generate(&mut adversarial_entropy());
			let keys_b = Keypair::generate(&mut adversarial_entropy());

			// Genuine keypair bytes must round-trip.
			let good = keys_a.to_bytes();
			assert!(
				Keypair::from_bytes(good.as_slice()).is_ok(),
				"honest keypair must be accepted"
			);

			// Splice A's secret key with B's (unrelated) public key.
			let mut forged = [0u8; KEYPAIRBYTES];
			forged[..SECRETKEYBYTES].copy_from_slice(keys_a.secret().to_bytes().as_slice());
			forged[SECRETKEYBYTES..].copy_from_slice(&keys_b.public().to_bytes());

			assert!(
				matches!(Keypair::from_bytes(&forged), Err(KeyParsingError::BadKeypair)),
				"public key not derived from the secret key must be rejected"
			);
		}

		// `from_parts` is the only way to assemble a `Keypair` from separately
		// imported halves (the fields are private), so it must enforce the
		// same secret/public correspondence as `from_bytes`.
		#[test]
		fn from_parts_enforces_secret_public_correspondence() {
			use super::{Keypair, SecretKey};
			use $crate::errors::KeyParsingError;

			let keys_a = Keypair::generate(&mut adversarial_entropy());
			let keys_b = Keypair::generate(&mut adversarial_entropy());

			let secret_a = SecretKey::from_bytes(keys_a.secret().to_bytes().as_slice()).unwrap();
			assert!(
				matches!(
					Keypair::from_parts(secret_a, keys_b.public().clone()),
					Err(KeyParsingError::BadKeypair)
				),
				"unrelated halves must be rejected"
			);

			let secret_a = SecretKey::from_bytes(keys_a.secret().to_bytes().as_slice()).unwrap();
			let assembled = Keypair::from_parts(secret_a, keys_a.public().clone())
				.expect("matching halves must be accepted");
			assert_eq!(*assembled.to_bytes(), *keys_a.to_bytes());
		}

		// The packed secret key stores tr = SHAKE256(pk) and t0 (low bits of
		// A·s1 + s2) alongside (rho, s1, s2). Signing uses the stored tr and
		// t0, so a blob with honest rho/s1/s2/pk but a corrupted tr or t0
		// region would import cleanly and then produce signatures that fail
		// under the advertised public key. `from_bytes` must reject such
		// blobs at import.
		#[test]
		fn from_bytes_rejects_corrupted_tr_or_t0() {
			use super::{Keypair, K, SECRETKEYBYTES};
			use $crate::{
				errors::KeyParsingError,
				params::{POLYT0_PACKEDBYTES, SEEDBYTES, TR_BYTES},
			};

			let keys = Keypair::generate(&mut adversarial_entropy());
			let good = keys.to_bytes();
			assert!(
				Keypair::from_bytes(good.as_slice()).is_ok(),
				"honest keypair must be accepted"
			);

			// SK layout: rho (32) || key (32) || tr (64) || s1 || s2 || t0.
			let tr_offset = 2 * SEEDBYTES;
			let t0_offset = SECRETKEYBYTES - K * POLYT0_PACKEDBYTES;

			// Corrupt one byte inside the stored tr region only.
			let mut bad_tr = good.clone();
			bad_tr[tr_offset + TR_BYTES / 2] ^= 0x01;
			assert!(
				matches!(Keypair::from_bytes(bad_tr.as_slice()), Err(KeyParsingError::BadKeypair)),
				"secret key with corrupted tr must be rejected"
			);

			// Corrupt one byte inside the stored t0 region only.
			let mut bad_t0 = good;
			bad_t0[t0_offset] ^= 0x01;
			assert!(
				matches!(Keypair::from_bytes(bad_t0.as_slice()), Err(KeyParsingError::BadKeypair)),
				"secret key with corrupted t0 must be rejected"
			);
		}

		// The standalone SecretKey import path must enforce the same tr/t0
		// consistency defense as Keypair::from_bytes. Signing consumes the
		// stored tr (bound into the message digest) and t0 (hint
		// computation), so a corrupted standalone key would otherwise import
		// cleanly and then emit signatures that fail under the corresponding
		// public key — a persistent, hard-to-diagnose signing outage for
		// callers that store SecretKey alone.
		#[test]
		fn secret_key_from_bytes_rejects_corrupted_tr_or_t0() {
			use super::{Keypair, SecretKey, K, SECRETKEYBYTES};
			use $crate::{
				errors::KeyParsingError,
				params::{POLYT0_PACKEDBYTES, SEEDBYTES, TR_BYTES},
			};

			let keys = Keypair::generate(&mut adversarial_entropy());
			let good = keys.secret().to_bytes();
			assert!(
				SecretKey::from_bytes(good.as_slice()).is_ok(),
				"honest secret key must be accepted"
			);

			// SK layout: rho (32) || key (32) || tr (64) || s1 || s2 || t0.
			let tr_offset = 2 * SEEDBYTES;
			let t0_offset = SECRETKEYBYTES - K * POLYT0_PACKEDBYTES;

			// Corrupt one byte inside the stored tr region only.
			let mut bad_tr = good.clone();
			bad_tr[tr_offset + TR_BYTES / 2] ^= 0x01;
			assert!(
				matches!(
					SecretKey::from_bytes(bad_tr.as_slice()),
					Err(KeyParsingError::BadSecretKey)
				),
				"standalone secret key with corrupted tr must be rejected"
			);

			// Corrupt one byte inside the stored t0 region only.
			let mut bad_t0 = good;
			bad_t0[t0_offset] ^= 0x01;
			assert!(
				matches!(
					SecretKey::from_bytes(bad_t0.as_slice()),
					Err(KeyParsingError::BadSecretKey)
				),
				"standalone secret key with corrupted t0 must be rejected"
			);
		}

		// The standalone SecretKey import path must reject a secret key whose
		// derived public key has all-zero t1, matching PublicKey::from_bytes
		// and sign::verify. Such a blob (s1 = s2 = 0, hence t1 = t0 = 0)
		// passes the tr/t0 consistency checks by construction, so without an
		// explicit t1 check it imports cleanly and then produces signatures
		// that can never verify — while the degenerate public key it
		// corresponds to is exactly the malicious-key forgery class the
		// verifier rejects.
		#[test]
		fn secret_key_from_bytes_rejects_zero_t1() {
			use super::{SecretKey, ETA, K, L, PUBLICKEYBYTES, SECRETKEYBYTES};
			use $crate::{errors::KeyParsingError, packing, params, polyvec};

			// Craft a fully self-consistent secret key with s1 = s2 = 0:
			// t = A·0 + 0 = 0, so t1 = 0 and t0 = 0, and tr = SHAKE256(pk).
			let rho = [0x42u8; params::SEEDBYTES];
			let key = [0x17u8; params::SEEDBYTES];
			let s1 = polyvec::Polyvec::<L>::default();
			let s2 = polyvec::Polyvec::<K>::default();
			let t0 = polyvec::Polyvec::<K>::default();
			let t1 = polyvec::Polyvec::<K>::default();

			let mut pk = [0u8; PUBLICKEYBYTES];
			packing::pack_pk(&mut pk, &rho, &t1);
			let mut tr = [0u8; params::TR_BYTES];
			$crate::fips202::shake256(&mut tr, &pk);

			let mut sk = [0u8; SECRETKEYBYTES];
			packing::pack_sk::<K, L, ETA, SECRETKEYBYTES>(&mut sk, &rho, &tr, &key, &t0, &s1, &s2);

			assert!(
				matches!(SecretKey::from_bytes(&sk), Err(KeyParsingError::BadSecretKey)),
				"secret key deriving an all-zero t1 public key must be rejected"
			);
		}

		// The packed s1/s2 regions store `ETA - coefficient` per slot (3-bit
		// slots for ETA = 2, 4-bit slots for ETA = 4). Planting a coefficient
		// of -(ETA + 1) yields a representable but non-canonical slot
		// (slot 5 at ETA = 2, slot 9 at ETA = 4) — outside the [-ETA, ETA]
		// key distribution the parameters advertise and the BETA rejection
		// margin is sized for. An attacker can recompute t0/tr/pk *from* the
		// oversized coefficients, so every algebraic consistency check
		// passes; the import paths must therefore enforce the coefficient
		// range explicitly.
		#[test]
		fn from_bytes_rejects_out_of_range_secret_coefficients() {
			use super::{
				Keypair, SecretKey, ETA, K, KEYPAIRBYTES, L, PUBLICKEYBYTES, SECRETKEYBYTES,
			};
			use $crate::{errors::KeyParsingError, fips202, packing, params, polyvec};

			// Start from an honest key and re-derive everything after
			// planting the out-of-range coefficient, so the forged blob is
			// fully self-consistent (valid t0, tr, and matching public key).
			let keys = Keypair::generate(&mut adversarial_entropy());
			let sk_bytes = keys.secret().to_bytes();

			let mut rho = [0u8; params::SEEDBYTES];
			let mut tr = [0u8; params::TR_BYTES];
			let mut key = [0u8; params::SEEDBYTES];
			let mut t0 = polyvec::Polyvec::<K>::default();
			let mut s1 = polyvec::Polyvec::<L>::default();
			let mut s2 = polyvec::Polyvec::<K>::default();
			assert!(
				packing::unpack_sk::<K, L, ETA, SECRETKEYBYTES>(
					&mut rho, &mut tr, &mut key, &mut t0, &mut s1, &mut s2, &sk_bytes,
				),
				"honest key unpacks canonically"
			);

			// -(ETA + 1) packs as slot ETA + 1 + ETA (eta_pack stores
			// ETA - coeff), which fits the slot width for both encodings, so
			// the forged coefficient survives the pack/unpack round trip.
			s1.vec[0].coeffs_mut()[0] = -(ETA as i32) - 1;

			// Same derivation as keygen: t = A·s1 + s2, split into (t1, t0).
			let mut s1hat = s1.clone();
			polyvec::ntt(&mut s1hat);
			let mut t1 = polyvec::Polyvec::<K>::default();
			polyvec::matrix_pointwise_montgomery_streamed(&mut t1, &rho, &s1hat);
			polyvec::reduce(&mut t1);
			polyvec::invntt_tomont(&mut t1);
			polyvec::add(&mut t1, &s2);
			polyvec::caddq(&mut t1);
			let mut t0_forged = polyvec::Polyvec::<K>::default();
			polyvec::power2round(&mut t1, &mut t0_forged);

			let mut pk = [0u8; PUBLICKEYBYTES];
			packing::pack_pk(&mut pk, &rho, &t1);
			let mut tr_forged = [0u8; params::TR_BYTES];
			fips202::shake256(&mut tr_forged, &pk);

			let mut forged_sk = [0u8; SECRETKEYBYTES];
			packing::pack_sk::<K, L, ETA, SECRETKEYBYTES>(
				&mut forged_sk,
				&rho,
				&tr_forged,
				&key,
				&t0_forged,
				&s1,
				&s2,
			);

			assert!(
				matches!(SecretKey::from_bytes(&forged_sk), Err(KeyParsingError::BadSecretKey)),
				"secret key with a coefficient outside [-ETA, ETA] must be rejected"
			);

			let mut forged_kp = [0u8; KEYPAIRBYTES];
			forged_kp[..SECRETKEYBYTES].copy_from_slice(&forged_sk);
			forged_kp[SECRETKEYBYTES..].copy_from_slice(&pk);
			assert!(
				matches!(Keypair::from_bytes(&forged_kp), Err(KeyParsingError::BadKeypair)),
				"keypair with a secret coefficient outside [-ETA, ETA] must be rejected"
			);

			// Honest keys must still round-trip.
			assert!(
				SecretKey::from_bytes(sk_bytes.as_slice()).is_ok(),
				"honest secret key must be accepted"
			);
		}

		// Malicious-key forgery defense: a public key with an all-zero t1
		// makes verification independent of the challenge, enabling signature
		// forgery without a secret key. `from_bytes` must reject such a key
		// so it can never be constructed or stored.
		#[test]
		fn from_bytes_rejects_zero_t1_public_key() {
			use super::{Keypair, PublicKey, PUBLICKEYBYTES};
			use $crate::{errors::KeyParsingError, params};

			// Arbitrary rho, all-zero t1 region.
			let mut pk = [0u8; PUBLICKEYBYTES];
			pk[..params::SEEDBYTES].copy_from_slice(&[0x42u8; params::SEEDBYTES]);

			assert!(matches!(PublicKey::from_bytes(&pk), Err(KeyParsingError::BadPublicKey)));

			// A genuine public key must still round-trip through from_bytes.
			let keys = Keypair::generate(&mut adversarial_entropy());
			let good = keys.public().to_bytes();
			assert!(PublicKey::from_bytes(&good).is_ok());
		}
	};
}

#[cfg(test)]
pub(crate) use adversarial_import_tests;
