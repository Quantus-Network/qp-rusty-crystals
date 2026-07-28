//! Shared public-API surface for every ML-DSA parameter set.
//!
//! The [`define_ml_dsa`] macro expands to the concrete `Keypair` / `SecretKey` /
//! `PublicKey` types for one variant, wiring them to [`crate::sign`]'s
//! const-generic cores. Each of [`crate::ml_dsa_44`], [`crate::ml_dsa_65`], and
//! [`crate::ml_dsa_87`] is a one-line instantiation of this macro (plus any
//! variant-specific tests). Expanding the macro yields the same code that
//! previously lived only in `ml_dsa_87.rs`.

/// Define the public ML-DSA API for one parameter-set module.
///
/// `$mod_name` is the identifier of the invoking module (used to render the
/// doc examples with the correct path). `$params` must be a path to a module
/// exposing the FIPS 204 constants
/// (`K`, `L`, `ETA`, `TAU`, `GAMMA1`, `GAMMA2`, `OMEGA`, `C_DASH_BYTES`,
/// `POLYZ_PACKEDBYTES`, `POLYW1_PACKEDBYTES`, `PUBLICKEYBYTES`,
/// `SECRETKEYBYTES`, `SIGNBYTES`) — i.e. one of [`crate::params::ml_dsa_44`],
/// [`crate::params::ml_dsa_65`], or [`crate::params::ml_dsa_87`].
macro_rules! define_ml_dsa {
	($mod_name:ident, $params:path) => {
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
		/// compile:
		#[doc = concat!(
							"```compile_fail\n",
							"use qp_rusty_crystals_dilithium::", stringify!($mod_name),
							"::{Keypair, PublicKey, SecretKey};\n",
							"\n",
							"fn forge(secret: SecretKey, public: PublicKey) -> Keypair {\n",
							"    Keypair { secret, public } // ERROR: fields are private\n",
							"}\n",
							"```\n",
							"\n",
							"```compile_fail\n",
							"use qp_rusty_crystals_dilithium::", stringify!($mod_name),
							"::{Keypair, PublicKey};\n",
							"\n",
							"fn swap_public(kp: &mut Keypair, other: PublicKey) {\n",
							"    kp.public = other; // ERROR: field is private\n",
							"}\n",
							"```",
						)]
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
			/// Note: The entropy is moved here and zeroized after use, along with the derived
			/// secret key.
			pub fn generate(entropy: SensitiveBytes32) -> Keypair {
				let mut pk = [0u8; PUBLICKEYBYTES];
				let mut sk = [0u8; SECRETKEYBYTES];
				$crate::sign::keypair_var::<K, L, ETA, PUBLICKEYBYTES, SECRETKEYBYTES>(
					&mut pk, &mut sk, entropy,
				);
				let keypair = Keypair {
					// Constructed directly rather than via `SecretKey::from_bytes`:
					// a freshly generated key is consistent by construction, and the
					// import-path validation would redo the keygen-scale derivation.
					secret: SecretKey { bytes: sk },
					public: PublicKey::from_bytes(&pk).expect("Should never fail"),
				};
				sk.zeroize();
				keypair
			}

			/// The secret half.
			pub fn secret(&self) -> &SecretKey {
				&self.secret
			}

			/// The public half.
			pub fn public(&self) -> &PublicKey {
				&self.public
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
				let derived_public = $crate::sign::public_key_from_secret_var::<
					K,
					L,
					ETA,
					PUBLICKEYBYTES,
					SECRETKEYBYTES,
				>(&secret.bytes)
				.ok_or(KeyParsingError::BadKeypair)?;
				if derived_public != public.bytes {
					return Err(KeyParsingError::BadKeypair);
				}
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
			pub fn from_bytes(bytes: &[u8]) -> Result<Keypair, KeyParsingError> {
				if bytes.len() != SECRETKEYBYTES + PUBLICKEYBYTES {
					return Err(KeyParsingError::BadKeypair);
				}
				let (secret_slice, public_bytes) = bytes.split_at(SECRETKEYBYTES);
				let mut secret_bytes = Zeroizing::new([0u8; SECRETKEYBYTES]);
				secret_bytes.copy_from_slice(secret_slice);
				let public =
					PublicKey::from_bytes(public_bytes).map_err(|_| KeyParsingError::BadKeypair)?;

				let derived_public = $crate::sign::public_key_from_secret_var::<
					K,
					L,
					ETA,
					PUBLICKEYBYTES,
					SECRETKEYBYTES,
				>(&secret_bytes)
				.ok_or(KeyParsingError::BadKeypair)?;
				if derived_public != public.bytes {
					return Err(KeyParsingError::BadKeypair);
				}

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
			pub fn sign(
				&self,
				msg: &[u8],
				ctx: Option<&[u8]>,
				hedge: Option<[u8; SEEDBYTES]>,
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
			pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, KeyParsingError> {
				if bytes.len() != SECRETKEYBYTES {
					return Err(BadSecretKey);
				}
				let mut sk = Zeroizing::new([0u8; SECRETKEYBYTES]);
				sk.copy_from_slice(bytes);
				$crate::sign::public_key_from_secret_var::<K, L, ETA, PUBLICKEYBYTES, SECRETKEYBYTES>(
													&sk,
												)
												.ok_or(BadSecretKey)?;
				Ok(SecretKey { bytes: *sk })
			}

			/// Compute a signature for a given message.
			///
			/// See [`Keypair::sign`] for the argument contract, in particular the
			/// deterministic-vs-hedged trade-off of `hedge`.
			pub fn sign(
				&self,
				msg: &[u8],
				ctx: Option<&[u8]>,
				hedge: Option<[u8; SEEDBYTES]>,
			) -> Result<Signature, SignatureError> {
				if msg.len() > MAX_MESSAGE_SIZE {
					return Err(SignatureError::MessageTooLong);
				}
				match ctx {
					Some(x) => {
						if x.len() > 255 {
							return Err(SignatureError::ContextTooLong);
						}
						let x_len = x.len();
						let mut prefix = [0u8; 2 + 255];
						prefix[1] = x_len as u8;
						prefix[2..2 + x_len].copy_from_slice(x);
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
						>(&mut sig, &prefix[..2 + x_len], msg, &self.bytes, hedge);
						Ok(sig)
					},
					None => {
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
						>(&mut sig, &[0u8, 0u8], msg, &self.bytes, hedge);
						Ok(sig)
					},
				}
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
				match ctx {
					Some(x) => {
						if x.len() > 255 {
							return false;
						}
						let x_len = x.len();
						let mut prefix = [0u8; 2 + 255];
						prefix[1] = x_len as u8;
						prefix[2..2 + x_len].copy_from_slice(x);
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
						>(sig, &prefix[..2 + x_len], msg, &self.bytes)
					},
					None => $crate::sign::verify_var::<
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
					>(sig, &[0u8, 0u8], msg, &self.bytes),
				}
			}
		}
	};
}

pub(crate) use define_ml_dsa;
