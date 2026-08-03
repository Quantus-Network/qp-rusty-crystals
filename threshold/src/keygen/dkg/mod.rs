//! Distributed Key Generation (DKG) for threshold ML-DSA-87.
//!
//! This module implements a 4-round DKG protocol for threshold Dilithium.
//!
//! # Protocol Overview
//!
//! **Round 1: Shared secret establishment + commitment**
//! - Leaders (min(S) for each subset S) generate K_S and distribute via secure P2P
//! - All parties commit to random r_i: broadcast c_i = H(i, r_i)
//!
//! **Round 2: Reveal randomness**
//! - All parties reveal r_i
//! - Verify commitments: c_j = H(j, r_j)
//!
//! **Round 3: Derive secrets + commit to partial PKs (leaders only)**
//! - Compute global randomness R = r_1 || ... || r_N
//! - Leaders derive s_S = H_keygen(S, K_S, R) and compute t_S = A·s_S
//! - Leaders broadcast commitment to partial PK
//!
//! **Round 4: Reveal partial PKs + transcript signing**
//! - Leaders reveal t_S
//! - Non-leaders verify: recompute s_S from K_S and R, verify commitment
//! - All parties sign transcript with long-term key
//!
//! **Aggregate: Verify signatures + combine PKs**
//! - Verify all transcript signatures
//! - Compute final public key: t = Σ t_S
//!
//! # Channel Requirements
//!
//! All DKG messages require transport-level sender authentication:
//!
//! | Action | Transport requirement |
//! |--------|----------------------|
//! | `DkgAction::SendMany` (Rounds 1–4 broadcasts) | Authenticated broadcast (integrity + sender authentication) |
//! | `DkgAction::SendPrivate` (Round 1 K_S distribution) | **Authenticated encryption** (confidentiality + integrity + sender authentication) |
//!
//! The `from` argument to [`Dkg::message`] is trusted: it MUST be the
//! transport-authenticated identity of the sender, never derived from
//! attacker-controllable packet contents.
//!
//! For `DkgAction::SendPrivate(to, data)` the caller must ensure:
//! - **Confidentiality**: The message is encrypted so only the recipient can read it
//! - **Authenticity**: The recipient can verify the sender's identity
//! - **Integrity**: The message cannot be modified in transit
//!
//! Failure to provide these guarantees compromises the threshold scheme's security:
//! - Without encryption, an eavesdropper learns K_S and can compute subset shares
//! - Without authentication, an attacker could inject fake K_S values
//!
//! For `DkgAction::SendMany` broadcasts, confidentiality is not needed (the
//! payloads are public), but authenticity and integrity are: round buffers
//! keep the first message received per sender (a memory-exhaustion defense),
//! so on an unauthenticated transport an attacker who injects a forged
//! broadcast first occupies that participant's slot and the honest broadcast
//! is ignored. The forgery is detected by commitment or transcript
//! verification, but only as a late abort — repeated injection denies
//! completion of every session.
//!
//! # Security Properties and Limitations
//!
//! ## Provided guarantees
//! - Each party contributes randomness, so no single party controls the key
//! - Commitment scheme (Round 1/2) prevents parties from adapting r_i based on others
//! - Algebraic verification (Round 4) detects an inconsistent partial public key for any subset in
//!   which the verifier is a member (see the partial-key η-binding limitation below for subsets
//!   with no honest member)
//! - Transcript signing provides non-repudiation
//!
//! ## Known limitations
//!
//! **K_S is not commitment-bound (late-abort griefing possible):**
//!
//! The per-subset secret K_S sent in Round 1 is not covered by the Round 1
//! commitment scheme. Instead, K_S correctness is verified algebraically in
//! Round 4 when subset members check that their independently-derived partial
//! public keys match the leader's commitment.
//!
//! This means a malicious or faulty leader can:
//! 1. Send different K_S values to different subset members
//! 2. Send K_S to some members but not others
//! 3. Send an invalid K_S
//!
//! All of these are detected in Round 4 and cause the protocol to abort, but:
//! - Detection is abort-only (no blame attribution)
//! - The abort happens late in the protocol (after 4 rounds of communication)
//! - A malicious leader can grief by forcing repeated late aborts
//!
//! For environments where late-abort griefing is a concern, consider:
//! - Adding reputation/staking mechanisms at the application layer
//! - Implementing leader rotation on repeated failures
//! - Using a complaint round with blame attribution (not currently implemented)
//!
//! **Partial-key η-binding requires an honest subset member (secure-with-abort):**
//!
//! Round 4 verifies a leader's partial public key `t_S` against the prescribed
//! η-bounded derivation only when the verifier is itself a member of subset `S`
//! and therefore holds `K_S`: it re-derives `s_S = H_keygen(S, K_S, R)` and
//! checks `t_S == A·s_S`. A verifier outside `S` holds no `K_S`, and `t_S`
//! alone is an LWE sample — deciding whether it has an η-bounded preimage is the
//! LWE/SIS problem, so an outsider cannot check it. Detecting the bound would
//! require revealing the preimage `s_S`, but the full secret is `s = Σ_S s_S`,
//! so publishing every `s_S` would expose the entire key; the only parties
//! entitled to learn `s_S` are `S`'s members, who can already verify. There is
//! thus no "reveal-and-check" that closes the gap without a zero-knowledge proof
//! of short preimage.
//!
//! Consequently, for a subset with **no honest member** a malicious leader can
//! commit to (and later reveal) a `t_S` that is not the prescribed η-bounded
//! derivation, and no honest party detects it. This is reachable *below* the
//! signing threshold:
//! - every subset in an n-of-n config is a singleton `{i}` (subset size `k = n - t + 1 = 1`), so a
//!   single malicious party owns its own subset;
//! - in configs with `k ≤ t - 1` (e.g. 3-of-4) a sub-threshold coalition can fully own a subset.
//!
//! The impact is bounded and consistent with the secure-with-abort model:
//! - **No forgery, no secret recovery.** The Round 3 commitment is opened only in Round 4, so a
//!   leader is bound to its `t_S` before any honest `t` is revealed; it cannot adaptively steer the
//!   aggregate `Σ_S t_S` toward a chosen or self-signable key, and it never learns honest subsets'
//!   shares.
//! - **Worst case is abort/retry or a bounded distribution skew.** A bogus `t_S` either fails the
//!   signing-time norm checks (persistent signing failure → abort and retry with a fresh
//!   session/participant set) or, if the leader picks a short-but-not-η preimage that still passes
//!   those checks, widens the aggregate secret distribution within the hyperball headroom.
//! - **No new halting power.** In exactly the configs where a subset can be fully corrupt below
//!   threshold, that adversary already lies in every signing quorum covering the subset (any `t`
//!   parties intersect every size-`(n − t + 1)` subset), so it can already force an abort by
//!   withholding.
//!
//! DKG therefore yields a provably η-distributed key only when every subset
//! contains at least one honest party. Where that does not hold, integrity
//! degrades to detect-and-abort rather than robust completion. Deployments that
//! require a guaranteed η-distributed output despite a fully-corrupt subset must
//! attach a zero-knowledge proof of short preimage to each partial key (not
//! implemented).
//!
//! **Coefficient distribution deviates from standard ML-DSA:**
//!
//! The reconstructed secret is the sum of `C(n, n-t+1)` independent η-bounded
//! shares (η=2 for ML-DSA-87), producing a wider coefficient distribution than
//! standard ML-DSA's single η-bounded secret. This is intrinsic to the Replicated
//! Secret Sharing (RSS) design.
//!
//! This coefficient growth cannot be exploited by malicious participants: each
//! subset share is derived deterministically via `H_keygen(S, K_S, R)` using
//! `uniform_eta`, guaranteeing η-bounded coefficients regardless of adversarial input.
//!
//! The hyperball sampling parameters are pre-computed to accommodate this wider
//! distribution with substantial safety margins (>99% headroom in tested
//! configurations). Coefficient ranges are monitored by the analysis helpers
//! in the integration test suite (see `threshold/tests/resharing_tests.rs`).
//!
//! # Usage
//!
//! ```ignore
//! use qp_rusty_crystals_threshold::keygen::dkg::{
//!     Dkg, DkgConfig, DkgAction,
//! };
//!
//! // Create configuration with a transcript signer
//! let config = DkgConfig::new(
//!     threshold_config,
//!     my_party_id,
//!     all_participants,
//!     my_signer,
//!     participant_public_keys,
//! )?;
//!
//! let mut dkg = Dkg::new(config, rng);
//!
//! loop {
//!     match dkg.poke()? {
//!         DkgAction::Wait => { /* wait for messages */ }
//!         DkgAction::SendMany(data) => { /* broadcast */ }
//!         DkgAction::SendPrivate(to, data) => {
//!             // MUST use authenticated + encrypted channel!
//!             secure_send_to(to, data).await?;
//!         }
//!         DkgAction::Return(output) => {
//!             // DKG complete!
//!             break;
//!         }
//!     }
//! }
//! ```
//!
//! # Compatibility
//!
//! The DKG produces `PrivateKeyShare` and `PublicKey` types that are fully
//! compatible with the existing threshold signing protocol. Shares generated
//! by DKG can be used directly with `ThresholdSigner`.
//!
//! # NEAR MPC Compatibility
//!
//! The `Dkg` struct follows the poke/message pattern used by NEAR's
//! `cait-sith` crate, making it compatible with NEAR MPC's `run_protocol`
//! infrastructure.
//!
//! # Liveness Considerations
//!
//! This implementation uses a sans-I/O architecture where the protocol logic is
//! decoupled from networking. **The networking layer is responsible for implementing
//! timeouts and failure detection.**
//!
//! Key liveness concerns that must be handled by the networking layer:
//!
//! - **Leader failure**: In Round 1, subset leaders send private `K_S` messages to subset members.
//!   If a leader fails to send these messages, members of that subset will wait indefinitely.
//!
//! - **Broadcast delays**: If any party fails to broadcast in any round, other parties will wait at
//!   `DkgAction::Wait`.
//!
//! - **Partial failures**: If some parties complete while others fail, the protocol may need to be
//!   restarted with a new participant set.
//!
//! Recommended approach: wrap the entire protocol execution in a timeout and
//! implement connection liveness checks during `Wait` periods:
//!
//! ```ignore
//! use std::time::Duration;
//!
//! let timeout = Duration::from_secs(60);
//!
//! let result = tokio::time::timeout(timeout, async {
//!     loop {
//!         match dkg.poke()? {
//!             DkgAction::Wait => {
//!                 // Check connection liveness while waiting
//!                 if !all_participants_connected() {
//!                     return Err("participant disconnected");
//!                 }
//!                 // Wait for next message from network
//!                 let (from, data) = receive_message().await?;
//!                 dkg.message(from, data)?;
//!             }
//!             DkgAction::SendMany(data) => broadcast(data).await?,
//!             DkgAction::SendPrivate(to, data) => send_to(to, data).await?,
//!             DkgAction::Return(output) => return Ok(output),
//!         }
//!     }
//! }).await??;
//! ```

mod protocol;
mod state;
mod types;

// Re-export public types.
//
// The completion predicates `all_broadcasts_received` and
// `all_private_messages_received` are deliberately not re-exported: both
// take raw slices and return "complete" for an empty one (vacuous truth),
// which is only sound because every in-crate caller passes
// `DkgConfig`-validated inputs. See the invariants section of `DkgConfig`'s
// docs, which pins both with compile_fail tests.
pub use protocol::{run_local_dkg, Dkg, DkgAction, DkgError};
pub use state::{DkgOutput, DkgPhase, DkgState};
pub use types::{
	compute_dkg_ssid,
	compute_partial_output_hash,
	compute_signing_message,
	compute_transcript_hash,
	derive_subset_contribution,
	// Hash functions
	h_commit,
	h_commit_pk,
	h_keygen,
	h_seed,
	// Configuration
	DkgConfig,
	// Message types
	DkgMessage,
	PartialPublicKey,
	Round1Broadcast,
	Round1Private,
	Round2Broadcast,
	Round3Broadcast,
	Round4Broadcast,
	// Core types
	SubsetContribution,
	SubsetMask,
	// Transcript signing
	TranscriptSigner,
	// Constants
	COMMITMENT_HASH_SIZE,
	// Constants
	DKG_SSID_SIZE,
	DOMAIN_COMMIT,
	DOMAIN_KEYGEN,
	DOMAIN_PK_COMMIT,
	DOMAIN_SEED,
	DOMAIN_TRANSCRIPT,
	MAX_TRANSCRIPT_SIGNATURE_SIZE,
	RANDOMNESS_SIZE,
	SHARED_SECRET_SIZE,
	SUBSET_SEED_SIZE,
};

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::{vec, vec::Vec};

	/// Test session nonce for DKG tests.
	const TEST_SESSION_NONCE: [u8; 32] = [0xDF; 32];

	#[derive(Clone, Debug, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
	struct TestSigner {
		id: u32,
	}

	impl TranscriptSigner for TestSigner {
		type Signature = Vec<u8>;
		type PublicKey = u32;

		fn sign(&self, hash: &[u8; 32]) -> Self::Signature {
			let mut sig = vec![0u8; 36];
			sig[..4].copy_from_slice(&self.id.to_le_bytes());
			sig[4..36].copy_from_slice(hash);
			sig
		}

		fn verify(pk: &Self::PublicKey, hash: &[u8; 32], sig: &Self::Signature) -> bool {
			Self::verify_bytes(pk, hash, sig)
		}

		fn verify_bytes(pk: &Self::PublicKey, hash: &[u8; 32], sig: &[u8]) -> bool {
			if sig.len() < 36 {
				return false;
			}
			let sig_id = u32::from_le_bytes(sig[..4].try_into().unwrap());
			sig_id == *pk && &sig[4..36] == hash
		}

		fn public_key(&self) -> Self::PublicKey {
			self.id
		}
	}

	#[test]
	fn test_dkg_2_of_3() {
		let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();
		let public_keys: Vec<u32> = (0..3).collect();
		let seed = [42u8; 32];

		let result = run_local_dkg(2, 3, signers, public_keys, seed, &TEST_SESSION_NONCE);

		match &result {
			Ok(outputs) => {
				assert_eq!(outputs.len(), 3);

				let pk0 = outputs[0].public_key.as_bytes();
				let pk1 = outputs[1].public_key.as_bytes();
				let pk2 = outputs[2].public_key.as_bytes();

				assert_eq!(pk0, pk1);
				assert_eq!(pk1, pk2);
			},
			Err(e) => {
				panic!("DKG failed: {:?}", e);
			},
		}
	}

	#[test]
	fn test_dkg_eta_bounded() {
		use crate::params::ETA;

		let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();
		let public_keys: Vec<u32> = (0..3).collect();
		let seed = [123u8; 32];

		let outputs = run_local_dkg(2, 3, signers, public_keys, seed, &TEST_SESSION_NONCE).unwrap();

		for (party_id, output) in outputs.iter().enumerate() {
			let shares = output.private_share.shares();
			for (subset_mask, share) in shares {
				for (poly_idx, poly) in share.s1.iter().enumerate() {
					for (coeff_idx, &coeff) in poly.iter().enumerate() {
						assert!(
							(-(ETA as i32)..=(ETA as i32)).contains(&coeff),
							"Party {} subset {:b} s1[{}][{}] = {} outside η bound",
							party_id,
							subset_mask,
							poly_idx,
							coeff_idx,
							coeff
						);
					}
				}
				for (poly_idx, poly) in share.s2.iter().enumerate() {
					for (coeff_idx, &coeff) in poly.iter().enumerate() {
						assert!(
							(-(ETA as i32)..=(ETA as i32)).contains(&coeff),
							"Party {} subset {:b} s2[{}][{}] = {} outside η bound",
							party_id,
							subset_mask,
							poly_idx,
							coeff_idx,
							coeff
						);
					}
				}
			}
		}
	}

	/// Test that DKG-generated keys work with ThresholdSigner for signing
	#[test]
	fn test_dkg_signing_integration() {
		use crate::{
			participants::ParticipantList, protocol::signing::compute_ssid, verify_signature,
			ThresholdConfig, ThresholdSigner,
		};

		let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();
		let public_keys: Vec<u32> = (0..3).collect();
		let seed = [99u8; 32];

		let dkg_outputs =
			run_local_dkg(2, 3, signers, public_keys, seed, &TEST_SESSION_NONCE).unwrap();

		// All parties should have the same public key
		let public_key = dkg_outputs[0].public_key.clone();
		for output in &dkg_outputs[1..] {
			assert_eq!(public_key.as_bytes(), output.public_key.as_bytes());
		}

		let config = ThresholdConfig::new(2, 3).unwrap();
		let message = b"Test message for DKG signing";
		let context = b"test-context";

		// Signing participants: first 2 parties
		let signing_participants = vec![0u32, 1u32];
		let participant_list = ParticipantList::new(&signing_participants).unwrap();

		// Retry signing up to 100 times (rejection sampling may fail)
		let mut success = false;
		for attempt in 0u8..100 {
			// Create fresh signers for each attempt
			let mut signers: Vec<ThresholdSigner> = dkg_outputs
				.iter()
				.take(2)
				.map(|output| {
					ThresholdSigner::new(output.private_share.clone(), public_key.clone(), config)
						.unwrap()
				})
				.collect();

			// Compute SSID for this attempt
			let mut attempt_nonce = [0u8; 32];
			attempt_nonce[0] = attempt;
			attempt_nonce[1] = 0xD2; // marker for dkg tests
			let ssid = compute_ssid(
				&public_key,
				2,
				3,
				&participant_list,
				message,
				context,
				&attempt_nonce,
			);

			// Round 1: Generate commitments using deterministic seeds
			let r1_broadcasts: Vec<_> = signers
				.iter_mut()
				.enumerate()
				.map(|(i, s)| {
					// Deterministic seed: unique per party and attempt
					let mut seed = [0u8; 32];
					seed[0] = i as u8;
					seed[1] = attempt;
					seed[2] = 0xD1; // marker for dkg tests
					s.round1_commit_with_seed(&ssid, &seed).unwrap()
				})
				.collect();

			// Round 2: Reveal commitments
			let r2_broadcasts: Vec<_> = signers
				.iter_mut()
				.enumerate()
				.map(|(i, s)| {
					let others: Vec<_> =
						r1_broadcasts.iter().filter(|r| r.party_id != i as u32).cloned().collect();
					s.round2_reveal(&ssid, message, context, &others).unwrap()
				})
				.collect();

			// Round 3: Compute responses
			let r3_broadcasts: Vec<_> = signers
				.iter_mut()
				.enumerate()
				.map(|(i, s)| {
					let others_r1: Vec<_> =
						r1_broadcasts.iter().filter(|r| r.party_id != i as u32).cloned().collect();
					let others_r2: Vec<_> =
						r2_broadcasts.iter().filter(|r| r.party_id != i as u32).cloned().collect();
					s.round3_respond(&ssid, &others_r1, &others_r2).unwrap()
				})
				.collect();

			// Try to combine signature (may fail due to rejection sampling)
			if let Ok(signature) = signers[0].combine(&r2_broadcasts, &r3_broadcasts) {
				// Verify signature
				assert!(
					verify_signature(&public_key, message, context, &signature),
					"Signature from DKG-generated keys should verify"
				);
				success = true;
				break;
			}
		}

		assert!(success, "Signing with DKG keys should succeed within 100 attempts");
	}
}
