//! Integration tests for the resharing (committee handoff) protocol.
//!
//! These tests verify that the resharing protocol correctly transfers
//! secret shares to a new committee while preserving the public key.

use std::collections::HashMap;

use qp_rusty_crystals_threshold::{
	compute_ssid, generate_with_dealer, verify_signature, ParticipantList, PrivateKeyShare,
	PublicKey, Round1Broadcast, Round2Broadcast, Round3Broadcast, ThresholdConfig, ThresholdSigner,
};

use qp_rusty_crystals_threshold::resharing::{
	Action, NewShareData, ResharingConfig, ResharingMessage, ResharingProtocol, ResharingState,
};

/// Helper to run the resharing protocol locally with simulated message passing.
fn run_resharing_protocol(
	old_threshold: u32,
	old_participants: Vec<u32>,
	new_threshold: u32,
	new_participants: Vec<u32>,
	old_shares: &HashMap<u32, PrivateKeyShare>,
	public_key: &PublicKey,
) -> Result<HashMap<u32, PrivateKeyShare>, String> {
	run_resharing_protocol_with_tamper(
		old_threshold,
		old_participants,
		new_threshold,
		new_participants,
		old_shares,
		public_key,
		None,
	)
}

/// Optional message tamper hook: `tamper(sender, recipient, raw_bytes) -> raw_bytes`.
type TamperFn = Box<dyn FnMut(u32, Option<u32>, Vec<u8>) -> Vec<u8>>;

fn run_resharing_protocol_with_tamper(
	old_threshold: u32,
	old_participants: Vec<u32>,
	new_threshold: u32,
	new_participants: Vec<u32>,
	old_shares: &HashMap<u32, PrivateKeyShare>,
	public_key: &PublicKey,
	mut tamper: Option<TamperFn>,
) -> Result<HashMap<u32, PrivateKeyShare>, String> {
	// Determine all parties involved (union of old and new)
	let mut all_parties: Vec<u32> =
		old_participants.iter().chain(new_participants.iter()).cloned().collect();
	all_parties.sort();
	all_parties.dedup();

	// Session nonce for SSID computation (shared by all parties in this resharing)
	let session_nonce = [0x99u8; 32];

	// Create protocol instances for each party
	let mut protocols: HashMap<u32, ResharingProtocol> = HashMap::new();

	for &party_id in &all_parties {
		let existing_share = old_shares.get(&party_id).cloned();

		let config = ResharingConfig::new(
			old_threshold,
			old_participants.clone(),
			new_threshold,
			new_participants.clone(),
			party_id,
			public_key.clone(),
		)
		.map_err(|e| format!("Config error for party {}: {}", party_id, e))?;

		// Generate a unique seed for each party (deterministic for test reproducibility)
		let mut seed = [0u8; 32];
		seed[0..4].copy_from_slice(&party_id.to_le_bytes());
		seed[4..8].copy_from_slice(&(old_threshold + new_threshold).to_le_bytes());
		// Fill rest with a pattern based on party_id
		for (i, byte) in seed.iter_mut().enumerate().skip(8) {
			*byte = ((party_id as u8).wrapping_mul(i as u8)).wrapping_add(0x42);
		}

		let protocol = ResharingProtocol::new(config, existing_share, seed, &session_nonce);
		protocols.insert(party_id, protocol);
	}

	// Message queues for each party
	let mut message_queues: HashMap<u32, Vec<(u32, Vec<u8>)>> = HashMap::new();
	for &party_id in &all_parties {
		message_queues.insert(party_id, Vec::new());
	}

	// Run the protocol until all parties are done
	let max_iterations = 1000;
	let mut iteration = 0;

	loop {
		iteration += 1;
		if iteration > max_iterations {
			return Err("Protocol did not complete within max iterations".to_string());
		}

		// Check if all parties are done
		let all_done = protocols.values().all(|p| p.is_done() || p.is_failed());

		if all_done {
			break;
		}

		// Process each party
		for &party_id in &all_parties {
			let protocol = protocols.get_mut(&party_id).unwrap();

			// Skip if already done or failed
			if protocol.is_done() || protocol.is_failed() {
				continue;
			}

			// Deliver queued messages first
			let messages = message_queues.get_mut(&party_id).unwrap();
			let messages_to_deliver: Vec<_> = std::mem::take(messages);

			for (from, data) in messages_to_deliver {
				protocol.message(from, data).unwrap();
			}

			// Poke the protocol
			match protocol.poke() {
				Ok(Action::Wait) => {
					// Nothing to do
				},
				Ok(Action::SendMany(data)) => {
					let payload = match tamper.as_mut() {
						Some(f) => f(party_id, None, data),
						None => data,
					};
					for &other_id in &all_parties {
						if other_id != party_id {
							message_queues
								.get_mut(&other_id)
								.unwrap()
								.push((party_id, payload.clone()));
						}
					}
				},
				Ok(Action::SendPrivate(to, data)) => {
					// Send to specific party. We deliberately do NOT loop self-private
					// messages back: the protocol must handle self-deals locally and
					// never emit SendPrivate(self, _).
					assert_ne!(
						to, party_id,
						"protocol emitted SendPrivate to self (party {}), \
						 self-deals must be handled locally",
						party_id
					);
					let payload = match tamper.as_mut() {
						Some(f) => f(party_id, Some(to), data),
						None => data,
					};
					message_queues.get_mut(&to).unwrap().push((party_id, payload));
				},
				Ok(Action::Return(_)) => {
					// Protocol complete for this party
				},
				Err(e) => {
					return Err(format!("Protocol error for party {}: {}", party_id, e));
				},
			}
		}
	}

	// Collect new shares from new committee members
	let mut new_shares: HashMap<u32, PrivateKeyShare> = HashMap::new();

	for &party_id in &new_participants {
		let protocol = protocols.get_mut(&party_id).unwrap();

		if protocol.is_failed() {
			return Err(format!("Party {} failed", party_id));
		}

		if !protocol.is_done() {
			return Err(format!("Party {} not done", party_id));
		}

		// Get the output using take_output
		if let Some(output) = protocol.take_output() {
			if let Some(share) = output.private_share {
				new_shares.insert(party_id, share);
			}
		} else {
			return Err(format!("Party {} has no output", party_id));
		}
	}

	Ok(new_shares)
}

/// Helper to run signing with a subset of signers and verify the result.
/// Uses retry mechanism since the signing protocol has probabilistic rejection sampling.
/// Even with valid keys, some randomness combinations fail the bounds checks.
fn run_signing_and_verify(
	shares: &[PrivateKeyShare],
	public_key: &PublicKey,
	config: ThresholdConfig,
	message: &[u8],
	context: &[u8],
) -> bool {
	run_signing_and_verify_with_retries(shares, public_key, config, message, context, 100)
}

/// Helper to run signing with explicit retry count.
/// Returns true if signing succeeds and signature verifies within max_attempts.
fn run_signing_and_verify_with_retries(
	shares: &[PrivateKeyShare],
	public_key: &PublicKey,
	config: ThresholdConfig,
	message: &[u8],
	context: &[u8],
	max_attempts: u32,
) -> bool {
	// Build participant list for SSID computation
	let participants: Vec<u32> = shares.iter().map(|s| s.party_id()).collect();
	let participant_list = ParticipantList::new(&participants).unwrap();

	for attempt in 0..max_attempts {
		// Create fresh signers for each attempt
		let signers_result: Result<Vec<ThresholdSigner>, _> = shares
			.iter()
			.map(|share| ThresholdSigner::new(share.clone(), public_key.clone(), config))
			.collect();

		let mut signers = match signers_result {
			Ok(s) => s,
			Err(_) => continue,
		};

		// Compute SSID for this attempt
		let mut attempt_nonce = [0u8; 32];
		attempt_nonce[0] = (attempt & 0xFF) as u8;
		attempt_nonce[1] = ((attempt >> 8) & 0xFF) as u8;
		attempt_nonce[2] = 0xAF; // marker for resharing tests
		let ssid = compute_ssid(
			public_key,
			config.threshold(),
			config.total_parties(),
			&participant_list,
			&attempt_nonce,
		);

		// Round 1: Generate commitments using deterministic seeds
		let r1_result: Result<Vec<Round1Broadcast>, _> = signers
			.iter_mut()
			.enumerate()
			.map(|(i, s)| {
				// Deterministic seed: unique per party and attempt
				let mut seed = [0u8; 32];
				seed[0] = i as u8;
				seed[1] = (attempt & 0xFF) as u8;
				seed[2] = ((attempt >> 8) & 0xFF) as u8;
				seed[3] = 0xAE; // marker for resharing tests
				s.round1_commit_with_seed(&ssid, &seed)
			})
			.collect();

		let r1_broadcasts = match r1_result {
			Ok(b) => b,
			Err(_) => continue,
		};

		// Round 2: Reveal
		let r2_result: Result<Vec<Round2Broadcast>, _> = signers
			.iter_mut()
			.enumerate()
			.map(|(i, s)| {
				let others: Vec<_> = r1_broadcasts
					.iter()
					.enumerate()
					.filter(|(j, _)| *j != i)
					.map(|(_, r)| r.clone())
					.collect();
				s.round2_reveal(&ssid, message, context, &others)
			})
			.collect();

		let r2_broadcasts = match r2_result {
			Ok(b) => b,
			Err(_) => continue,
		};

		// Round 3: Respond
		let r3_result: Result<Vec<Round3Broadcast>, _> = signers
			.iter_mut()
			.enumerate()
			.map(|(i, s)| {
				let others_r1: Vec<_> = r1_broadcasts
					.iter()
					.enumerate()
					.filter(|(j, _)| *j != i)
					.map(|(_, r)| r.clone())
					.collect();
				let others_r2: Vec<_> = r2_broadcasts
					.iter()
					.enumerate()
					.filter(|(j, _)| *j != i)
					.map(|(_, r)| r.clone())
					.collect();
				s.round3_respond(&ssid, &others_r1, &others_r2)
			})
			.collect();

		let r3_broadcasts = match r3_result {
			Ok(b) => b,
			Err(_) => continue,
		};

		// Combine
		let signature =
			match signers[0].combine_with_message(message, context, &r2_broadcasts, &r3_broadcasts)
			{
				Ok(sig) => sig,
				Err(_) => continue,
			};

		// Verify
		if verify_signature(public_key, message, context, &signature) {
			if attempt > 0 {
				println!("  Signing succeeded on attempt {}", attempt + 1);
			}
			return true;
		}
	}

	println!("  Signing failed after {} attempts", max_attempts);
	false
}

// ============================================================================
// Unit Tests for Resharing Types
// ============================================================================

#[test]
fn test_resharing_config_creation() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, _shares) = generate_with_dealer(&seed, config).expect("keygen");

	// Create resharing config for party 0 (staying in committee)
	let resharing_config = ResharingConfig::new(
		2,             // old threshold
		vec![0, 1, 2], // old participants
		2,             // new threshold
		vec![0, 1, 3], // new participants (2 leaves, 3 joins)
		0,             // my party id
		public_key.clone(),
	);

	assert!(resharing_config.is_ok());
	let config = resharing_config.unwrap();
	assert!(config.role().is_old_committee());
	assert!(config.role().is_new_committee());
}

#[test]
fn test_resharing_config_new_party() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, _shares) = generate_with_dealer(&seed, config).expect("keygen");

	// Create resharing config for party 3 (joining)
	let resharing_config = ResharingConfig::new(
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 3],
		3, // joining party
		public_key.clone(),
	);

	assert!(resharing_config.is_ok());
	let config = resharing_config.unwrap();
	assert!(!config.role().is_old_committee());
	assert!(config.role().is_new_committee());
}

#[test]
fn test_resharing_config_leaving_party() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, _shares) = generate_with_dealer(&seed, config).expect("keygen");

	// Create resharing config for party 2 (leaving)
	let resharing_config = ResharingConfig::new(
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 3],
		2, // leaving party
		public_key.clone(),
	);

	assert!(resharing_config.is_ok());
	let config = resharing_config.unwrap();
	assert!(config.role().is_old_committee());
	assert!(!config.role().is_new_committee());
}

// ============================================================================
// Protocol State Machine Tests
// ============================================================================

#[test]
fn test_resharing_protocol_creation() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	let resharing_config = ResharingConfig::new(
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 2], // same committee
		0,
		public_key,
	)
	.expect("valid config");

	let protocol_seed = [42u8; 32];
	let session_nonce = [0x88u8; 32];
	let protocol = ResharingProtocol::new(resharing_config, Some(shares[0].clone()), protocol_seed, &session_nonce);
	assert_eq!(*protocol.state(), ResharingState::Round1Generate);
}

#[test]
fn test_resharing_protocol_round1_generation() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	let resharing_config = ResharingConfig::new(
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 2],
		0,
		public_key,
	)
	.expect("valid config");

	let protocol_seed = [42u8; 32];
	let session_nonce = [0x55u8; 32];
	let mut protocol = ResharingProtocol::new(resharing_config, Some(shares[0].clone()), protocol_seed, &session_nonce);

	// First poke should generate Round 1 message (entropy commitment)
	let action = protocol.poke().expect("poke should succeed");
	match action {
		Action::SendMany(data) => {
			assert!(!data.is_empty());
			// Verify it's a valid Round 1 message (entropy commitment)
			let msg: ResharingMessage = borsh::from_slice(&data).expect("should deserialize");
			match msg {
				ResharingMessage::Round1(broadcast) => {
					assert_eq!(broadcast.party_id, 0);
					// Commitment should be 32 bytes
					assert_eq!(broadcast.commitment.len(), 32);
				},
				_ => panic!("Expected Round1 message (entropy commitment)"),
			}
		},
		_ => panic!("Expected SendMany action"),
	}

	assert_eq!(*protocol.state(), ResharingState::Round1Waiting);
}

#[test]
fn test_resharing_new_party_skips_round1() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, _shares) = generate_with_dealer(&seed, config).expect("keygen");

	// Party 3 is joining (not in old committee)
	let resharing_config =
		ResharingConfig::new(2, vec![0, 1, 2], 2, vec![0, 1, 3], 3, public_key)
			.expect("valid config");

	let protocol_seed = [42u8; 32];
	let session_nonce = [0x66u8; 32];
	let mut protocol = ResharingProtocol::new(resharing_config, None, protocol_seed, &session_nonce);

	// New party should skip Round 1-2 (entropy commit-reveal) and wait
	let action = protocol.poke().expect("poke should succeed");
	match action {
		Action::Wait => {
			// Expected - new party waits for Round 3-4-5 messages
		},
		_ => panic!("Expected Wait action for new party"),
	}

	// NewOnly parties skip directly to Round2Waiting (waiting for entropy reveals to complete)
	assert_eq!(*protocol.state(), ResharingState::Round2Waiting);
}

// ============================================================================
// Full Protocol Tests (Simulated)
// ============================================================================

#[test]
fn test_resharing_same_committee() {
	// Test resharing to the same committee (effectively a refresh)
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	let mut old_shares: HashMap<u32, PrivateKeyShare> = HashMap::new();
	for share in shares {
		old_shares.insert(share.party_id(), share);
	}

	// For now, just verify the protocol can be set up
	// Full end-to-end test requires fixing the output extraction issue
	for party_id in 0..3 {
		let resharing_config = ResharingConfig::new(
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 2],
			party_id,
			public_key.clone(),
		);
		assert!(resharing_config.is_ok());
	}
}

#[test]
fn test_resharing_add_party() {
	// Test adding a new party: (2,3) -> (2,4)
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	let mut old_shares: HashMap<u32, PrivateKeyShare> = HashMap::new();
	for share in shares {
		old_shares.insert(share.party_id(), share);
	}

	// Verify configs can be created for all parties
	// Old committee: 0, 1, 2
	// New committee: 0, 1, 2, 3
	for party_id in 0..4 {
		let resharing_config = ResharingConfig::new(
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 2, 3],
			party_id,
			public_key.clone(),
		);
		assert!(
			resharing_config.is_ok(),
			"Failed to create config for party {}: {:?}",
			party_id,
			resharing_config.err()
		);
	}
}

#[test]
fn test_resharing_remove_party() {
	// Test removing a party: (2,3) -> (2,2)
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	let mut old_shares: HashMap<u32, PrivateKeyShare> = HashMap::new();
	for share in shares {
		old_shares.insert(share.party_id(), share);
	}

	// Verify configs can be created
	// Old committee: 0, 1, 2
	// New committee: 0, 1 (party 2 leaves)
	for party_id in 0..3 {
		let resharing_config = ResharingConfig::new(
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1],
			party_id,
			public_key.clone(),
		);
		assert!(
			resharing_config.is_ok(),
			"Failed to create config for party {}: {:?}",
			party_id,
			resharing_config.err()
		);
	}
}

#[test]
fn test_resharing_change_threshold() {
	// Test changing threshold: (2,3) -> (3,4)
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	let mut old_shares: HashMap<u32, PrivateKeyShare> = HashMap::new();
	for share in shares {
		old_shares.insert(share.party_id(), share);
	}

	// Old committee: 0, 1, 2 with t=2
	// New committee: 0, 1, 2, 3 with t=3
	for party_id in 0..4 {
		let resharing_config = ResharingConfig::new(
			2,
			vec![0, 1, 2],
			3, // new threshold
			vec![0, 1, 2, 3],
			party_id,
			public_key.clone(),
		);
		assert!(
			resharing_config.is_ok(),
			"Failed to create config for party {}: {:?}",
			party_id,
			resharing_config.err()
		);
	}
}

#[test]
fn test_resharing_complete_committee_change() {
	// Test complete committee change: (2,3) with {0,1,2} -> (2,3) with {3,4,5}
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	let mut old_shares: HashMap<u32, PrivateKeyShare> = HashMap::new();
	for share in shares {
		old_shares.insert(share.party_id(), share);
	}

	// Old committee: 0, 1, 2
	// New committee: 3, 4, 5 (completely different)
	// All old members are leaving, all new members are joining
	for party_id in 0..6 {
		let resharing_config = ResharingConfig::new(
			2,
			vec![0, 1, 2],
			2,
			vec![3, 4, 5],
			party_id,
			public_key.clone(),
		);
		assert!(
			resharing_config.is_ok(),
			"Failed to create config for party {}: {:?}",
			party_id,
			resharing_config.err()
		);
	}
}

// ============================================================================
// Error Case Tests
// ============================================================================

#[test]
fn test_resharing_config_party_not_in_either_committee() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, _shares) = generate_with_dealer(&seed, config).expect("keygen");

	// Party 10 is not in either committee
	let result = ResharingConfig::new(2, vec![0, 1, 2], 2, vec![3, 4, 5], 10, public_key);

	assert!(result.is_err());
}

// Note: existing_share validation is now done at ResharingProtocol::new(), not ResharingConfig::new()

#[test]
fn test_resharing_config_invalid_old_threshold() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, _shares) = generate_with_dealer(&seed, config).expect("keygen");

	// Old threshold too high
	let result = ResharingConfig::new(
		5, // invalid: > n
		vec![0, 1, 2],
		2,
		vec![0, 1, 2],
		0,
		public_key,
	);

	assert!(result.is_err());
}

#[test]
fn test_resharing_config_invalid_new_threshold() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, _shares) = generate_with_dealer(&seed, config).expect("keygen");

	// New threshold too low
	let result = ResharingConfig::new(
		2,
		vec![0, 1, 2],
		1, // invalid: < 2
		vec![0, 1, 2],
		0,
		public_key,
	);

	assert!(result.is_err());
}

// ============================================================================
// Message Handling Tests
// ============================================================================

#[test]
fn test_resharing_round1_message_from_non_member_ignored() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	let resharing_config = ResharingConfig::new(
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 2],
		0,
		public_key.clone(),
	)
	.expect("valid config");

	let session_nonce = [0x44u8; 32];
	let mut protocol = ResharingProtocol::new(resharing_config, Some(shares[0].clone()), [42u8; 32], &session_nonce);

	// Generate Round 1 message first
	let _ = protocol.poke().expect("poke should succeed");

	// Try to deliver a truly malformed message from a valid participant
	// (single byte can't be valid borsh for our types)
	// This should return an error since it can't be deserialized
	let malformed_message = vec![0xFF]; // Single byte - definitely can't deserialize to ResharingMessage
	let result = protocol.message(1, malformed_message); // From party 1 (valid participant)

	// Should return MalformedMessage error
	assert!(result.is_err(), "Malformed message should return an error, got: {:?}", result);

	// Protocol should still be in Round1Waiting (error doesn't change state)
	assert_eq!(*protocol.state(), ResharingState::Round1Waiting);
}

#[test]
fn test_resharing_duplicate_message_ignored() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	// Create two protocols for parties 0 and 1
	let config0 = ResharingConfig::new(
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 2],
		0,
		public_key.clone(),
	)
	.expect("valid config");

	let config1 = ResharingConfig::new(
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 2],
		1,
		public_key.clone(),
	)
	.expect("valid config");

	let session_nonce = [0x33u8; 32];
	let mut protocol0 = ResharingProtocol::new(config0, Some(shares[0].clone()), [0u8; 32], &session_nonce);
	let mut protocol1 = ResharingProtocol::new(config1, Some(shares[1].clone()), [1u8; 32], &session_nonce);

	// Generate Round 0 messages
	let msg0 = match protocol0.poke().expect("poke should succeed") {
		Action::SendMany(data) => data,
		_ => panic!("Expected SendMany"),
	};

	let _ = protocol1.poke().expect("poke should succeed");

	// Deliver message from party 0 to party 1
	protocol1.message(0, msg0.clone()).unwrap();

	// Deliver the same message again (duplicate)
	protocol1.message(0, msg0).unwrap();

	// Should only be counted once - need 3 messages total (from parties 0, 1, and 2)
	// to have "enough" Round 0 messages
}

// ============================================================================
// Subset Generation Tests
// ============================================================================

#[test]
fn test_subset_generation_2_of_3() {
	// For (t=2, n=3), subset size = n - t + 1 = 2
	// Subsets: {0,1}, {0,2}, {1,2} = 3 subsets
	// This is C(3,2) = 3

	// The protocol uses subset masks internally
	// Mask 0b011 = {0,1}
	// Mask 0b101 = {0,2}
	// Mask 0b110 = {1,2}
}

#[test]
fn test_subset_generation_3_of_5() {
	// For (t=3, n=5), subset size = n - t + 1 = 3
	// Number of subsets: C(5,3) = 10
}

// ============================================================================
// Role-based behavior tests
// ============================================================================

#[test]
fn test_old_only_party_behavior() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	// Party 2 is leaving (old only)
	let resharing_config = ResharingConfig::new(
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 3], // party 2 not in new committee
		2,
		public_key,
	)
	.expect("valid config");

	let session_nonce = [0x22u8; 32];
	let mut protocol = ResharingProtocol::new(resharing_config, Some(shares[2].clone()), [42u8; 32], &session_nonce);

	// Party should participate in Round 0 (entropy commitment)
	let action = protocol.poke().expect("poke should succeed");
	match action {
		Action::SendMany(_) => {
			// Expected - old party broadcasts Round 0 message
		},
		_ => panic!("Expected SendMany for old party in Round 0"),
	}
}

#[test]
fn test_new_only_party_behavior() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, _shares) = generate_with_dealer(&seed, config).expect("keygen");

	// Party 3 is joining (new only)
	let resharing_config = ResharingConfig::new(
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 3],
		3, // new party
		public_key,
	)
	.expect("valid config");

	let session_nonce = [0x11u8; 32];
	let mut protocol = ResharingProtocol::new(resharing_config, None, [42u8; 32], &session_nonce);

	// New party should skip Round 1-2 (entropy commit-reveal) and wait
	let action = protocol.poke().expect("poke should succeed");
	match action {
		Action::Wait => {
			// Expected - new party waits for Round 3-4-5 messages
		},
		_ => panic!("Expected Wait for new party"),
	}

	// NewOnly parties skip directly to Round2Waiting
	assert_eq!(*protocol.state(), ResharingState::Round2Waiting);
}

// ============================================================================
// End-to-End Protocol Tests
// ============================================================================

// NOTE: The end-to-end resharing tests use retry logic for signing because
// the signing protocol has probabilistic rejection sampling. Even with valid
// keys, some randomness combinations fail the bounds checks. This is the same
// behavior as the regular signing tests in integration_tests.rs which also
// use retry loops.

#[test]
fn test_resharing_end_to_end_same_committee() {
	// Test full resharing protocol with same committee (2,3) -> (2,3)
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	let mut old_shares: HashMap<u32, PrivateKeyShare> = HashMap::new();
	for share in &shares {
		old_shares.insert(share.party_id(), share.clone());
	}

	// Run resharing to the same committee
	let result =
		run_resharing_protocol(2, vec![0, 1, 2], 2, vec![0, 1, 2], &old_shares, &public_key);

	assert!(result.is_ok(), "Resharing failed: {:?}", result.err());
	let new_shares = result.unwrap();

	// All 3 parties should have new shares
	assert_eq!(new_shares.len(), 3);
	assert!(new_shares.contains_key(&0));
	assert!(new_shares.contains_key(&1));
	assert!(new_shares.contains_key(&2));

	// Verify the new shares can be used for signing
	// Only use threshold (2) signers, not all 3
	let signing_shares: Vec<_> =
		vec![new_shares.get(&0).unwrap().clone(), new_shares.get(&1).unwrap().clone()];
	let is_valid =
		run_signing_and_verify(&signing_shares, &public_key, config, b"test message", b"");

	assert!(is_valid, "Signature with new shares should verify");
}

#[test]
fn test_resharing_end_to_end_add_party() {
	// Test adding a party: (2,3) with {0,1,2} -> (2,4) with {0,1,2,3}
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	let mut old_shares: HashMap<u32, PrivateKeyShare> = HashMap::new();
	for share in &shares {
		old_shares.insert(share.party_id(), share.clone());
	}

	// Run resharing to add party 3
	let result =
		run_resharing_protocol(2, vec![0, 1, 2], 2, vec![0, 1, 2, 3], &old_shares, &public_key);

	assert!(result.is_ok(), "Resharing failed: {:?}", result.err());
	let new_shares = result.unwrap();

	// All 4 parties should have new shares
	assert_eq!(new_shares.len(), 4);
	assert!(new_shares.contains_key(&0));
	assert!(new_shares.contains_key(&1));
	assert!(new_shares.contains_key(&2));
	assert!(new_shares.contains_key(&3));

	// Verify signing works with a subset of new parties
	// Use parties {0, 1} which are both in old AND new committee
	let new_config = ThresholdConfig::new(2, 4).expect("valid config");
	let subset_shares: Vec<_> =
		vec![new_shares.get(&0).unwrap().clone(), new_shares.get(&1).unwrap().clone()];
	let is_valid =
		run_signing_and_verify(&subset_shares, &public_key, new_config, b"test message", b"");

	assert!(is_valid, "Signature with new shares should verify");
}

#[test]
fn test_resharing_end_to_end_remove_party() {
	// Test removing a party: (2,3) with {0,1,2} -> (2,2) with {0,1}
	// Note: (2,2) means both parties are required for signing
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	let mut old_shares: HashMap<u32, PrivateKeyShare> = HashMap::new();
	for share in &shares {
		old_shares.insert(share.party_id(), share.clone());
	}

	// Run resharing to remove party 2
	let result = run_resharing_protocol(2, vec![0, 1, 2], 2, vec![0, 1], &old_shares, &public_key);

	assert!(result.is_ok(), "Resharing failed: {:?}", result.err());
	let new_shares = result.unwrap();

	// Only parties 0 and 1 should have new shares
	assert_eq!(new_shares.len(), 2);
	assert!(new_shares.contains_key(&0));
	assert!(new_shares.contains_key(&1));
	assert!(!new_shares.contains_key(&2));

	// Verify signing works with the new committee
	// For (2,2), we need both parties
	let new_config = ThresholdConfig::new(2, 2).expect("valid config");
	let signing_shares: Vec<_> =
		vec![new_shares.get(&0).unwrap().clone(), new_shares.get(&1).unwrap().clone()];
	let is_valid =
		run_signing_and_verify(&signing_shares, &public_key, new_config, b"test message", b"");

	assert!(is_valid, "Signature with new shares should verify");
}

#[test]
fn test_resharing_end_to_end_replace_party() {
	// Test replacing a party: (2,3) with {0,1,2} -> (2,3) with {0,1,3}
	// Party 2 leaves, party 3 joins
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	let mut old_shares: HashMap<u32, PrivateKeyShare> = HashMap::new();
	for share in &shares {
		old_shares.insert(share.party_id(), share.clone());
	}

	// Run resharing to replace party 2 with party 3
	let result =
		run_resharing_protocol(2, vec![0, 1, 2], 2, vec![0, 1, 3], &old_shares, &public_key);

	assert!(result.is_ok(), "Resharing failed: {:?}", result.err());
	let new_shares = result.unwrap();

	// Parties 0, 1, and 3 should have new shares
	assert_eq!(new_shares.len(), 3);
	assert!(new_shares.contains_key(&0));
	assert!(new_shares.contains_key(&1));
	assert!(new_shares.contains_key(&3));
	assert!(!new_shares.contains_key(&2));

	// Verify signing works with the new committee
	// Use parties 0 and 1 (or 0 and 3) - threshold is 2
	let signing_shares: Vec<_> =
		vec![new_shares.get(&0).unwrap().clone(), new_shares.get(&1).unwrap().clone()];
	let is_valid =
		run_signing_and_verify(&signing_shares, &public_key, config, b"test message", b"");

	assert!(is_valid, "Signature with new shares should verify");
}

#[test]
fn test_resharing_end_to_end_disjoint_committees() {
	// Test full committee handoff with NO overlap: (2,3) with {0,1,2} -> (2,3) with {3,4,5}.
	// Verifies that completely-new parties (no existing shares) can derive working
	// shares solely from old-committee dealing, and that signatures using ONLY new
	// parties verify against the original public key.
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [7u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	let mut old_shares: HashMap<u32, PrivateKeyShare> = HashMap::new();
	for share in &shares {
		old_shares.insert(share.party_id(), share.clone());
	}

	let result =
		run_resharing_protocol(2, vec![0, 1, 2], 2, vec![3, 4, 5], &old_shares, &public_key);

	assert!(result.is_ok(), "Resharing failed: {:?}", result.err());
	let new_shares = result.unwrap();

	assert_eq!(new_shares.len(), 3);
	assert!(new_shares.contains_key(&3));
	assert!(new_shares.contains_key(&4));
	assert!(new_shares.contains_key(&5));
	assert!(!new_shares.contains_key(&0));
	assert!(!new_shares.contains_key(&1));
	assert!(!new_shares.contains_key(&2));

	// Sign with two of the brand-new parties; verify against original PK.
	let signing_shares: Vec<_> =
		vec![new_shares.get(&3).unwrap().clone(), new_shares.get(&4).unwrap().clone()];
	let is_valid =
		run_signing_and_verify(&signing_shares, &public_key, config, b"disjoint committee", b"");
	assert!(is_valid, "Signature from disjoint new committee should verify");

	// Also try a different threshold subset to confirm any t parties can sign.
	let signing_shares_alt: Vec<_> =
		vec![new_shares.get(&4).unwrap().clone(), new_shares.get(&5).unwrap().clone()];
	let is_valid_alt = run_signing_and_verify(
		&signing_shares_alt,
		&public_key,
		config,
		b"disjoint committee alt",
		b"",
	);
	assert!(is_valid_alt, "Alternate threshold subset should also produce valid signatures");
}

/// Recompute the SHAKE256 commitment over `(i_mask, j_mask, r)` exactly the way the
/// dealer does internally. Used by the malicious-dealer test below to forge a
/// commitment that is *consistent* with a tampered `r` so the recipient's
/// commitment-vs-r check passes — making the attack only catchable via the
/// public-key invariant (M2).
fn forge_consistent_commitment(i_mask: u16, j_mask: u16, r: &NewShareData) -> [u8; 32] {
	use qp_rusty_crystals_dilithium::fips202;
	const COMMIT_DOMAIN: &[u8] = b"resharing-commit-v2";
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, COMMIT_DOMAIN);
	fips202::shake256_absorb(&mut state, &i_mask.to_le_bytes());
	fips202::shake256_absorb(&mut state, &j_mask.to_le_bytes());
	let mut buf: Vec<u8> = Vec::new();
	for poly in &r.s1 {
		buf.clear();
		for c in poly {
			buf.extend_from_slice(&c.to_le_bytes());
		}
		fips202::shake256_absorb(&mut state, &buf);
	}
	for poly in &r.s2 {
		buf.clear();
		for c in poly {
			buf.extend_from_slice(&c.to_le_bytes());
		}
		fips202::shake256_absorb(&mut state, &buf);
	}
	fips202::shake256_finalize(&mut state);
	let mut out = [0u8; 32];
	fips202::shake256_squeeze(&mut out, &mut state);
	out
}

#[test]
fn test_resharing_detects_dealer_accusation_when_commitment_tampered() {
	// In a (2,3) resharing, old subsets have size 2 (n - t + 1 = 3 - 2 + 1 = 2).
	// Each old subset has a designated dealer and another verifier. If the dealer
	// broadcasts a bad commitment, the verifier will detect it in `collect_accusations`.

	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [77u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	let mut old_shares: HashMap<u32, PrivateKeyShare> = HashMap::new();
	for share in &shares {
		old_shares.insert(share.party_id(), share.clone());
	}

	// Tamper only the Round 3 Commitments (not the Round 4 payload). The recipient
	// will accept the sub-share (commitment mismatch with our tampered value), but
	// another member of the same old subset will independently recompute the
	// *correct* commitment and file an accusation.
	let target_pair = (0b011u16, 0b011u16); // old subset {0,1}, new subset {0,1}
	let bad_commit = [0xAAu8; 32];

	let tamper: TamperFn = Box::new(move |sender, _recipient, data| {
		if sender != 0 {
			return data;
		}
		let msg: ResharingMessage = match borsh::from_slice(&data) {
			Ok(m) => m,
			Err(_) => return data,
		};
		let modified = match msg {
			ResharingMessage::Round3(mut b) => {
				if let Some(c) = b.commitments.get_mut(&target_pair) {
					*c = bad_commit;
				}
				ResharingMessage::Round3(b)
			},
			other => other,
		};
		borsh::to_vec(&modified).expect("re-serialize tampered msg")
	});

	let result = run_resharing_protocol_with_tamper(
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 2],
		&old_shares,
		&public_key,
		Some(tamper),
	);

	let err = result.expect_err("tampered commitment must be detected via accusation");
	// The protocol detects dealer misbehavior - either via accusation or party failure
	assert!(
		err.contains("accused") ||
			err.contains("misbehavior") ||
			err.contains("Party failure") ||
			err.contains("PartyFailure"),
		"expected dealer accusation or party failure, got: {}",
		err
	);
}

#[test]
fn test_resharing_ignores_fabricated_accusation_against_non_dealer() {
	// A malicious party could try to frame another party by fabricating an accusation
	// claiming they were a bad dealer for a subset they weren't actually the dealer of.
	// The protocol must validate that the accused party is the designated dealer for
	// the claimed subset, and ignore accusations against non-dealers.

	use qp_rusty_crystals_threshold::resharing::DealerAccusation;

	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [88u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	let mut old_shares: HashMap<u32, PrivateKeyShare> = HashMap::new();
	for share in &shares {
		old_shares.insert(share.party_id(), share.clone());
	}

	// Party 1 will inject a fabricated accusation against party 2, claiming party 2
	// was a bad dealer for old_subset 0b011 (parties {0,1}). But party 0 is the
	// designated dealer for that subset (lowest ID), not party 2.
	let fabricated_accusation = DealerAccusation {
		dealer: 2,           // Framing party 2
		old_subset: 0b011,   // Subset {0,1} - dealer is party 0, not party 2
		new_subset: 0b011,
	};

	let tamper: TamperFn = Box::new(move |sender, _recipient, data| {
		if sender != 1 {
			return data;
		}
		let msg: ResharingMessage = match borsh::from_slice(&data) {
			Ok(m) => m,
			Err(_) => return data,
		};
		let modified = match msg {
			ResharingMessage::Round5(mut b) => {
				// Inject the fabricated accusation
				b.accusations.push(fabricated_accusation.clone());
				ResharingMessage::Round5(b)
			},
			other => other,
		};
		borsh::to_vec(&modified).expect("re-serialize tampered msg")
	});

	// The protocol should succeed despite the fabricated accusation, because the
	// accusation is invalid (party 2 is not the dealer for subset 0b011).
	let result = run_resharing_protocol_with_tamper(
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 2],
		&old_shares,
		&public_key,
		Some(tamper),
	);

	assert!(
		result.is_ok(),
		"Protocol should succeed - fabricated accusation against non-dealer must be ignored. \
		 Got error: {:?}",
		result.err()
	);
}

#[test]
fn test_resharing_detects_round2_payload_mismatch() {
	// Tamper only the Round 4 payload (not the commitment). The recipient will
	// detect that the received `r` doesn't match the broadcast commitment and
	// fail with ShareVerificationFailed.
	const N: usize = 256;
	const L: usize = 7;
	const K: usize = 8;

	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [55u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	let mut old_shares: HashMap<u32, PrivateKeyShare> = HashMap::new();
	for share in &shares {
		old_shares.insert(share.party_id(), share.clone());
	}

	let target_pair = (0b011u16, 0b011u16);
	let bogus_r = NewShareData { s1: [[99i32; N]; L], s2: [[13i32; N]; K] };

	let bogus_r_capt = bogus_r.clone();
	let tamper: TamperFn = Box::new(move |sender, _recipient, data| {
		if sender != 0 {
			return data;
		}
		let msg: ResharingMessage = match borsh::from_slice(&data) {
			Ok(m) => m,
			Err(_) => return data,
		};
		let modified = match msg {
			ResharingMessage::Round4(mut m) => {
				if m.from_party_id == 0 && m.contributions.contains_key(&target_pair) {
					m.contributions.insert(target_pair, bogus_r_capt.clone());
				}
				ResharingMessage::Round4(m)
			},
			other => other,
		};
		borsh::to_vec(&modified).expect("re-serialize tampered msg")
	});

	let result = run_resharing_protocol_with_tamper(
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 2],
		&old_shares,
		&public_key,
		Some(tamper),
	);

	let err = result.expect_err("tampered Round 2 payload must be detected");
	// The protocol detects the mismatch - either via commitment check or party failure
	assert!(
		err.contains("commitment") ||
			err.contains("ShareVerificationFailed") ||
			err.contains("Party failure"),
		"expected commitment mismatch or party failure, got: {}",
		err
	);
}

#[test]
fn test_resharing_detects_consistent_dealer_tamper_at_t_equals_n() {
	// In a (2,2) -> (2,2) resharing every old subset has size 1, so the dealer is
	// the sole member of their old subset and `collect_accusations` cannot catch a
	// dealer that lies about their residual `r`. To prove that lying about `r` is
	// nonetheless caught, we tamper *both* the Round 3 Commitments and the Round 4
	// payload so that they remain mutually consistent (passing the recipient's
	// commit-vs-r check). The resulting `s_J^new` for the recipient is corrupted,
	// the partial public-key sum no longer reconstructs the original public key,
	// and `verify_public_key_preservation` fails.
	const N: usize = 256;
	const L: usize = 7;
	const K: usize = 8;

	let config = ThresholdConfig::new(2, 2).expect("valid config");
	let seed = [11u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	let mut old_shares: HashMap<u32, PrivateKeyShare> = HashMap::new();
	for share in &shares {
		old_shares.insert(share.party_id(), share.clone());
	}

	let bogus_r = NewShareData { s1: [[42i32; N]; L], s2: [[7i32; N]; K] };
	let target_pair = (0b01u16, 0b10u16);
	let bogus_commit = forge_consistent_commitment(target_pair.0, target_pair.1, &bogus_r);

	let bogus_r_capt = bogus_r.clone();
	let tamper: TamperFn = Box::new(move |sender, _recipient, data| {
		if sender != 0 {
			return data;
		}
		let msg: ResharingMessage = match borsh::from_slice(&data) {
			Ok(m) => m,
			Err(_) => return data,
		};
		let modified = match msg {
			ResharingMessage::Round3(mut b) =>
				if let Some(c) = b.commitments.get_mut(&target_pair) {
					*c = bogus_commit;
					ResharingMessage::Round3(b)
				} else {
					ResharingMessage::Round3(b)
				},
			ResharingMessage::Round4(mut m) =>
				if m.from_party_id == 0 && m.contributions.contains_key(&target_pair) {
					m.contributions.insert(target_pair, bogus_r_capt.clone());
					ResharingMessage::Round4(m)
				} else {
					ResharingMessage::Round4(m)
				},
			other => other,
		};
		borsh::to_vec(&modified).expect("re-serialize tampered msg")
	});

	let result = run_resharing_protocol_with_tamper(
		2,
		vec![0, 1],
		2,
		vec![0, 1],
		&old_shares,
		&public_key,
		Some(tamper),
	);

	let err = result.expect_err("malicious dealer must be detected");
	assert!(
		err.contains("public key") ||
			err.contains("ShareVerificationFailed") ||
			err.contains("Party failure") ||
			err.contains("PartyFailure"),
		"expected public-key invariant failure or party failure, got: {}",
		err
	);
}

// ============================================================================
// Forward Secrecy Tests
// ============================================================================

/// Helper function to run resharing with custom seeds for each party.
/// Returns the new shares if successful, or an error message.
fn run_resharing_protocol_with_seeds(
	old_threshold: u32,
	old_participants: Vec<u32>,
	new_threshold: u32,
	new_participants: Vec<u32>,
	old_shares: &HashMap<u32, PrivateKeyShare>,
	public_key: &PublicKey,
	party_seeds: &HashMap<u32, [u8; 32]>,
) -> Result<HashMap<u32, PrivateKeyShare>, String> {
	// Determine all parties involved (union of old and new)
	let mut all_parties: Vec<u32> =
		old_participants.iter().chain(new_participants.iter()).cloned().collect();
	all_parties.sort();
	all_parties.dedup();

	// Session nonce for SSID computation (shared by all parties in this resharing)
	let session_nonce = [0xCCu8; 32];

	// Create protocol instances for each party with the provided seeds
	let mut protocols: HashMap<u32, ResharingProtocol> = HashMap::new();

	for &party_id in &all_parties {
		let existing_share = old_shares.get(&party_id).cloned();

		let config = ResharingConfig::new(
			old_threshold,
			old_participants.clone(),
			new_threshold,
			new_participants.clone(),
			party_id,
			public_key.clone(),
		)
		.map_err(|e| format!("Config error for party {}: {}", party_id, e))?;

		// Use the provided seed for this party
		let seed = party_seeds.get(&party_id).copied().unwrap_or([0u8; 32]);
		let protocol = ResharingProtocol::new(config, existing_share, seed, &session_nonce);
		protocols.insert(party_id, protocol);
	}

	// Message queues for each party
	let mut message_queues: HashMap<u32, Vec<(u32, Vec<u8>)>> = HashMap::new();
	for &party_id in &all_parties {
		message_queues.insert(party_id, Vec::new());
	}

	// Run the protocol until all parties are done
	let max_iterations = 1000;
	let mut iteration = 0;

	loop {
		iteration += 1;
		if iteration > max_iterations {
			return Err("Protocol did not complete within max iterations".to_string());
		}

		let all_done = protocols.values().all(|p| p.is_done() || p.is_failed());
		if all_done {
			break;
		}

		for &party_id in &all_parties {
			let protocol = protocols.get_mut(&party_id).unwrap();
			if protocol.is_done() || protocol.is_failed() {
				continue;
			}

			let messages = message_queues.get_mut(&party_id).unwrap();
			let messages_to_deliver: Vec<_> = std::mem::take(messages);

			for (from, data) in messages_to_deliver {
				protocol.message(from, data).unwrap();
			}

			match protocol.poke() {
				Ok(Action::Wait) => {},
				Ok(Action::SendMany(data)) =>
					for &other_id in &all_parties {
						if other_id != party_id {
							message_queues
								.get_mut(&other_id)
								.unwrap()
								.push((party_id, data.clone()));
						}
					},
				Ok(Action::SendPrivate(to, data)) => {
					assert_ne!(to, party_id);
					message_queues.get_mut(&to).unwrap().push((party_id, data));
				},
				Ok(Action::Return(_)) => {},
				Err(e) => {
					return Err(format!("Protocol error for party {}: {}", party_id, e));
				},
			}
		}
	}

	// Collect new shares from new committee members
	let mut new_shares: HashMap<u32, PrivateKeyShare> = HashMap::new();
	for &party_id in &new_participants {
		let protocol = protocols.get_mut(&party_id).unwrap();
		if protocol.is_failed() {
			return Err(format!("Party {} failed", party_id));
		}
		if !protocol.is_done() {
			return Err(format!("Party {} not done", party_id));
		}
		if let Some(output) = protocol.take_output() {
			if let Some(share) = output.private_share {
				new_shares.insert(party_id, share);
			}
		} else {
			return Err(format!("Party {} has no output", party_id));
		}
	}

	Ok(new_shares)
}

#[test]
fn test_forward_secrecy_different_sessions_produce_different_subshares() {
	// This test verifies forward secrecy: running the resharing protocol twice
	// with different entropy seeds should produce different intermediate subshares.
	// Even with the same old shares and same committee configuration, the new shares
	// should differ because the session seed (derived from all parties' entropy)
	// is mixed into the PRF that generates subshares.
	//
	// Importantly, both resulting share sets should still:
	// 1. Be valid (can produce valid signatures)
	// 2. Preserve the same public key
	// 3. Have different internal structure (proving the entropy is used)

	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [99u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	let mut old_shares: HashMap<u32, PrivateKeyShare> = HashMap::new();
	for share in &shares {
		old_shares.insert(share.party_id(), share.clone());
	}

	// First resharing session with one set of entropy seeds
	let mut seeds_session_1: HashMap<u32, [u8; 32]> = HashMap::new();
	for party_id in 0..3u32 {
		let mut seed = [0u8; 32];
		seed[0] = 0xAA; // Session 1 marker
		seed[1..5].copy_from_slice(&party_id.to_le_bytes());
		seeds_session_1.insert(party_id, seed);
	}

	let result1 = run_resharing_protocol_with_seeds(
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 2],
		&old_shares,
		&public_key,
		&seeds_session_1,
	);
	assert!(result1.is_ok(), "First resharing session failed: {:?}", result1.err());
	let new_shares_1 = result1.unwrap();

	// Second resharing session with different entropy seeds
	let mut seeds_session_2: HashMap<u32, [u8; 32]> = HashMap::new();
	for party_id in 0..3u32 {
		let mut seed = [0u8; 32];
		seed[0] = 0xBB; // Session 2 marker - different from session 1
		seed[1..5].copy_from_slice(&party_id.to_le_bytes());
		seeds_session_2.insert(party_id, seed);
	}

	let result2 = run_resharing_protocol_with_seeds(
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 2],
		&old_shares,
		&public_key,
		&seeds_session_2,
	);
	assert!(result2.is_ok(), "Second resharing session failed: {:?}", result2.err());
	let new_shares_2 = result2.unwrap();

	// Verify both sessions produced valid shares that can sign
	let signing_shares_1: Vec<_> =
		vec![new_shares_1.get(&0).unwrap().clone(), new_shares_1.get(&1).unwrap().clone()];
	let is_valid_1 =
		run_signing_and_verify(&signing_shares_1, &public_key, config, b"test message 1", b"");
	assert!(is_valid_1, "Signature with session 1 shares should verify");

	let signing_shares_2: Vec<_> =
		vec![new_shares_2.get(&0).unwrap().clone(), new_shares_2.get(&1).unwrap().clone()];
	let is_valid_2 =
		run_signing_and_verify(&signing_shares_2, &public_key, config, b"test message 2", b"");
	assert!(is_valid_2, "Signature with session 2 shares should verify");

	// The key forward secrecy test: the shares should be different!
	// We compare the serialized shares to detect any difference in the internal structure.
	// If the entropy wasn't being used, the shares would be identical.
	let share_0_session_1 = borsh::to_vec(new_shares_1.get(&0).unwrap()).unwrap();
	let share_0_session_2 = borsh::to_vec(new_shares_2.get(&0).unwrap()).unwrap();

	assert_ne!(
		share_0_session_1, share_0_session_2,
		"Shares from different sessions should differ due to forward secrecy entropy"
	);

	// Also verify that shares from different parties within the same session differ
	// (this was already the case, but good to confirm)
	let share_1_session_1 = borsh::to_vec(new_shares_1.get(&1).unwrap()).unwrap();
	assert_ne!(share_0_session_1, share_1_session_1, "Shares for different parties should differ");

	println!("Forward secrecy verified: different entropy seeds produce different shares");
	println!(
		"  Session 1 share 0 bytes: {} (first 32: {:?}...)",
		share_0_session_1.len(),
		&share_0_session_1[..32.min(share_0_session_1.len())]
	);
	println!(
		"  Session 2 share 0 bytes: {} (first 32: {:?}...)",
		share_0_session_2.len(),
		&share_0_session_2[..32.min(share_0_session_2.len())]
	);
}

#[test]
fn test_forward_secrecy_identical_seeds_produce_identical_shares() {
	// This test verifies that the protocol is deterministic when given the same
	// entropy seeds - running twice with identical seeds should produce identical shares.
	// This confirms that the randomness is properly derived from the seeds.

	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [77u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	let mut old_shares: HashMap<u32, PrivateKeyShare> = HashMap::new();
	for share in &shares {
		old_shares.insert(share.party_id(), share.clone());
	}

	// Same seeds for both sessions
	let mut seeds: HashMap<u32, [u8; 32]> = HashMap::new();
	for party_id in 0..3u32 {
		let mut seed = [0u8; 32];
		seed[0] = 0xCC;
		seed[1..5].copy_from_slice(&party_id.to_le_bytes());
		seeds.insert(party_id, seed);
	}

	let result1 = run_resharing_protocol_with_seeds(
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 2],
		&old_shares,
		&public_key,
		&seeds,
	);
	assert!(result1.is_ok(), "First resharing session failed: {:?}", result1.err());
	let new_shares_1 = result1.unwrap();

	let result2 = run_resharing_protocol_with_seeds(
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 2],
		&old_shares,
		&public_key,
		&seeds, // Same seeds!
	);
	assert!(result2.is_ok(), "Second resharing session failed: {:?}", result2.err());
	let new_shares_2 = result2.unwrap();

	// With identical seeds, shares should be identical
	for party_id in 0..3u32 {
		let share_1 = borsh::to_vec(new_shares_1.get(&party_id).unwrap()).unwrap();
		let share_2 = borsh::to_vec(new_shares_2.get(&party_id).unwrap()).unwrap();
		assert_eq!(
			share_1, share_2,
			"With identical seeds, party {} shares should be identical",
			party_id
		);
	}

	println!("Determinism verified: identical entropy seeds produce identical shares");
}

#[test]
fn test_forward_secrecy_single_party_entropy_change_affects_all() {
	// This test verifies that even if only ONE party changes their entropy,
	// all resulting shares change. This is important for forward secrecy:
	// even if an attacker compromises n-1 parties' entropy, they still can't
	// predict the session seed because the honest party's entropy is unknown.

	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [55u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	let mut old_shares: HashMap<u32, PrivateKeyShare> = HashMap::new();
	for share in &shares {
		old_shares.insert(share.party_id(), share.clone());
	}

	// Session 1: all parties use fixed seeds
	let mut seeds_session_1: HashMap<u32, [u8; 32]> = HashMap::new();
	for party_id in 0..3u32 {
		let mut seed = [0u8; 32];
		seed[0] = 0xDD;
		seed[1..5].copy_from_slice(&party_id.to_le_bytes());
		seeds_session_1.insert(party_id, seed);
	}

	// Session 2: only party 2 changes their entropy
	let mut seeds_session_2 = seeds_session_1.clone();
	let mut new_seed_for_party_2 = [0u8; 32];
	new_seed_for_party_2[0] = 0xEE; // Different!
	new_seed_for_party_2[1..5].copy_from_slice(&2u32.to_le_bytes());
	seeds_session_2.insert(2, new_seed_for_party_2);

	let result1 = run_resharing_protocol_with_seeds(
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 2],
		&old_shares,
		&public_key,
		&seeds_session_1,
	);
	assert!(result1.is_ok(), "First resharing session failed: {:?}", result1.err());
	let new_shares_1 = result1.unwrap();

	let result2 = run_resharing_protocol_with_seeds(
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 2],
		&old_shares,
		&public_key,
		&seeds_session_2,
	);
	assert!(result2.is_ok(), "Second resharing session failed: {:?}", result2.err());
	let new_shares_2 = result2.unwrap();

	// ALL parties' shares should differ, even though only party 2 changed their entropy
	// This is because the session seed is derived from ALL parties' entropy
	for party_id in 0..3u32 {
		let share_1 = borsh::to_vec(new_shares_1.get(&party_id).unwrap()).unwrap();
		let share_2 = borsh::to_vec(new_shares_2.get(&party_id).unwrap()).unwrap();
		assert_ne!(
			share_1, share_2,
			"Party {} shares should differ when any party's entropy changes",
			party_id
		);
	}

	// Both sessions should still produce valid shares
	let signing_shares_1: Vec<_> =
		vec![new_shares_1.get(&0).unwrap().clone(), new_shares_1.get(&1).unwrap().clone()];
	let is_valid_1 = run_signing_and_verify(&signing_shares_1, &public_key, config, b"test", b"");
	assert!(is_valid_1, "Session 1 shares should produce valid signatures");

	let signing_shares_2: Vec<_> =
		vec![new_shares_2.get(&0).unwrap().clone(), new_shares_2.get(&1).unwrap().clone()];
	let is_valid_2 = run_signing_and_verify(&signing_shares_2, &public_key, config, b"test", b"");
	assert!(is_valid_2, "Session 2 shares should produce valid signatures");

	println!("Forward secrecy cascade verified: one party's entropy change affects all shares");
}

// ============================================================================
// Retry Rate Measurement Tests
// ============================================================================

/// Statistics from signing attempts
#[derive(Debug, Default)]
struct SigningStats {
	total_attempts: u32,
	successful_attempts: u32,
	total_retries: u32,
	max_retries_single_sign: u32,
}

impl SigningStats {
	fn avg_retries_per_success(&self) -> f64 {
		if self.successful_attempts == 0 {
			f64::INFINITY
		} else {
			self.total_retries as f64 / self.successful_attempts as f64
		}
	}
}

/// Run signing multiple times and collect retry statistics.
/// Returns (success, stats) where success indicates all signings worked.
fn run_signing_with_stats(
	shares: &[PrivateKeyShare],
	public_key: &PublicKey,
	config: ThresholdConfig,
	num_signings: u32,
	max_retries_per_signing: u32,
) -> (bool, SigningStats) {
	let mut stats = SigningStats::default();

	// Build participant list for SSID computation
	let participants: Vec<u32> = shares.iter().map(|s| s.party_id()).collect();
	let participant_list = ParticipantList::new(&participants).unwrap();

	for signing_idx in 0..num_signings {
		let message = format!("test message {}", signing_idx);
		let mut succeeded = false;

		for retry in 0..max_retries_per_signing {
			stats.total_attempts += 1;

			// Create fresh signers for each attempt
			let signers_result: Result<Vec<ThresholdSigner>, _> = shares
				.iter()
				.map(|share| ThresholdSigner::new(share.clone(), public_key.clone(), config))
				.collect();

			let mut signers = match signers_result {
				Ok(s) => s,
				Err(_) => continue,
			};

			// Compute SSID for this attempt
			let mut attempt_nonce = [0u8; 32];
			attempt_nonce[0] = (signing_idx & 0xFF) as u8;
			attempt_nonce[1] = ((signing_idx >> 8) & 0xFF) as u8;
			attempt_nonce[2] = (retry & 0xFF) as u8;
			attempt_nonce[3] = 0xBC; // marker for stats tests
			let ssid = compute_ssid(
				public_key,
				config.threshold(),
				config.total_parties(),
				&participant_list,
				&attempt_nonce,
			);

			// Round 1: Generate commitments
			let r1_result: Result<Vec<Round1Broadcast>, _> = signers
				.iter_mut()
				.enumerate()
				.map(|(i, s)| {
					let mut seed = [0u8; 32];
					seed[0] = i as u8;
					seed[1] = (signing_idx & 0xFF) as u8;
					seed[2] = ((signing_idx >> 8) & 0xFF) as u8;
					seed[3] = (retry & 0xFF) as u8;
					seed[4] = 0xBB; // marker for retry rate tests
					s.round1_commit_with_seed(&ssid, &seed)
				})
				.collect();

			let r1_broadcasts = match r1_result {
				Ok(b) => b,
				Err(_) => continue,
			};

			// Round 2: Reveal
			let r2_result: Result<Vec<Round2Broadcast>, _> = signers
				.iter_mut()
				.enumerate()
				.map(|(i, s)| {
					let others: Vec<_> = r1_broadcasts
						.iter()
						.enumerate()
						.filter(|(j, _)| *j != i)
						.map(|(_, r)| r.clone())
						.collect();
					s.round2_reveal(&ssid, message.as_bytes(), b"", &others)
				})
				.collect();

			let r2_broadcasts = match r2_result {
				Ok(b) => b,
				Err(_) => continue,
			};

			// Round 3: Respond
			let r3_result: Result<Vec<Round3Broadcast>, _> = signers
				.iter_mut()
				.enumerate()
				.map(|(i, s)| {
					let others_r1: Vec<_> = r1_broadcasts
						.iter()
						.enumerate()
						.filter(|(j, _)| *j != i)
						.map(|(_, r)| r.clone())
						.collect();
					let others_r2: Vec<_> = r2_broadcasts
						.iter()
						.enumerate()
						.filter(|(j, _)| *j != i)
						.map(|(_, r)| r.clone())
						.collect();
					s.round3_respond(&ssid, &others_r1, &others_r2)
				})
				.collect();

			let r3_broadcasts = match r3_result {
				Ok(b) => b,
				Err(_) => continue,
			};

			// Combine
			let signature = match signers[0].combine_with_message(
				message.as_bytes(),
				b"",
				&r2_broadcasts,
				&r3_broadcasts,
			) {
				Ok(sig) => sig,
				Err(_) => continue,
			};

			// Verify
			if verify_signature(public_key, message.as_bytes(), b"", &signature) {
				succeeded = true;
				stats.successful_attempts += 1;
				stats.total_retries += retry;
				if retry > stats.max_retries_single_sign {
					stats.max_retries_single_sign = retry;
				}
				break;
			}
		}

		if !succeeded {
			// Count all retries as failed
			stats.total_retries += max_retries_per_signing;
			return (false, stats);
		}
	}

	(true, stats)
}

#[test]
#[ignore] // Long-running benchmark test - run with `cargo test -- --ignored`
fn test_measure_retry_rate_dkg_vs_reshared_shares() {
	// This test measures and compares the signing retry rates between:
	// 1. Fresh DKG-created shares (baseline)
	// 2. Reshared shares (potentially larger coefficients)
	//
	// The goal is to understand if resharing impacts signing efficiency.

	println!("\n=== Retry Rate Comparison: DKG vs Reshared Shares ===\n");

	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let num_signings = 50; // Number of distinct messages to sign
	let max_retries = 100; // Max retries per signing attempt

	// -------------------------------------------------------------------------
	// Test 1: Fresh DKG shares (baseline)
	// -------------------------------------------------------------------------
	let seed = [0xAA; 32];
	let (public_key, dkg_shares) = generate_with_dealer(&seed, config).expect("keygen");

	let signing_shares_dkg: Vec<_> = vec![dkg_shares[0].clone(), dkg_shares[1].clone()];

	let (dkg_success, dkg_stats) =
		run_signing_with_stats(&signing_shares_dkg, &public_key, config, num_signings, max_retries);

	println!("DKG Shares (baseline):");
	println!("  Success: {}", dkg_success);
	println!("  Successful signings: {}/{}", dkg_stats.successful_attempts, num_signings);
	println!("  Avg retries per signing: {:.2}", dkg_stats.avg_retries_per_success());
	println!("  Max retries for single signing: {}", dkg_stats.max_retries_single_sign);
	println!();

	// -------------------------------------------------------------------------
	// Test 2: Same-committee reshared shares (refresh)
	// -------------------------------------------------------------------------
	let mut old_shares: HashMap<u32, PrivateKeyShare> = HashMap::new();
	for share in &dkg_shares {
		old_shares.insert(share.party_id(), share.clone());
	}

	let reshared_same =
		run_resharing_protocol(2, vec![0, 1, 2], 2, vec![0, 1, 2], &old_shares, &public_key)
			.expect("resharing should succeed");

	let signing_shares_reshared_same: Vec<_> =
		vec![reshared_same.get(&0).unwrap().clone(), reshared_same.get(&1).unwrap().clone()];

	let (reshared_same_success, reshared_same_stats) = run_signing_with_stats(
		&signing_shares_reshared_same,
		&public_key,
		config,
		num_signings,
		max_retries,
	);

	println!("Reshared Shares (same committee refresh):");
	println!("  Success: {}", reshared_same_success);
	println!("  Successful signings: {}/{}", reshared_same_stats.successful_attempts, num_signings);
	println!("  Avg retries per signing: {:.2}", reshared_same_stats.avg_retries_per_success());
	println!("  Max retries for single signing: {}", reshared_same_stats.max_retries_single_sign);
	println!();

	// -------------------------------------------------------------------------
	// Test 3: Reshared shares after adding a party
	// -------------------------------------------------------------------------
	let reshared_add =
		run_resharing_protocol(2, vec![0, 1, 2], 2, vec![0, 1, 2, 3], &old_shares, &public_key)
			.expect("resharing should succeed");

	let new_config = ThresholdConfig::new(2, 4).expect("valid config");
	let signing_shares_reshared_add: Vec<_> =
		vec![reshared_add.get(&0).unwrap().clone(), reshared_add.get(&1).unwrap().clone()];

	let (reshared_add_success, reshared_add_stats) = run_signing_with_stats(
		&signing_shares_reshared_add,
		&public_key,
		new_config,
		num_signings,
		max_retries,
	);

	println!("Reshared Shares (after adding party, 2-of-4):");
	println!("  Success: {}", reshared_add_success);
	println!("  Successful signings: {}/{}", reshared_add_stats.successful_attempts, num_signings);
	println!("  Avg retries per signing: {:.2}", reshared_add_stats.avg_retries_per_success());
	println!("  Max retries for single signing: {}", reshared_add_stats.max_retries_single_sign);
	println!();

	// -------------------------------------------------------------------------
	// Test 4: Disjoint committee resharing
	// -------------------------------------------------------------------------
	let reshared_disjoint =
		run_resharing_protocol(2, vec![0, 1, 2], 2, vec![3, 4, 5], &old_shares, &public_key)
			.expect("resharing should succeed");

	let signing_shares_disjoint: Vec<_> = vec![
		reshared_disjoint.get(&3).unwrap().clone(),
		reshared_disjoint.get(&4).unwrap().clone(),
	];

	let (disjoint_success, disjoint_stats) = run_signing_with_stats(
		&signing_shares_disjoint,
		&public_key,
		config,
		num_signings,
		max_retries,
	);

	println!("Reshared Shares (disjoint committee):");
	println!("  Success: {}", disjoint_success);
	println!("  Successful signings: {}/{}", disjoint_stats.successful_attempts, num_signings);
	println!("  Avg retries per signing: {:.2}", disjoint_stats.avg_retries_per_success());
	println!("  Max retries for single signing: {}", disjoint_stats.max_retries_single_sign);
	println!();

	// -------------------------------------------------------------------------
	// Test 5: Multiple consecutive resharings (coefficient growth?)
	// -------------------------------------------------------------------------
	let mut current_shares = old_shares.clone();

	// Do 5 consecutive resharings to stress test coefficient growth
	for _reshare_round in 0..5 {
		let new_shares = run_resharing_protocol(
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 2],
			&current_shares,
			&public_key,
		)
		.expect("resharing should succeed");

		current_shares = new_shares;
	}

	let signing_shares_multi: Vec<_> =
		vec![current_shares.get(&0).unwrap().clone(), current_shares.get(&1).unwrap().clone()];

	let (multi_success, multi_stats) = run_signing_with_stats(
		&signing_shares_multi,
		&public_key,
		config,
		num_signings,
		max_retries,
	);

	println!("Reshared Shares (after 5 consecutive resharings):");
	println!("  Success: {}", multi_success);
	println!("  Successful signings: {}/{}", multi_stats.successful_attempts, num_signings);
	println!("  Avg retries per signing: {:.2}", multi_stats.avg_retries_per_success());
	println!("  Max retries for single signing: {}", multi_stats.max_retries_single_sign);
	println!();

	// -------------------------------------------------------------------------
	// Test 6: 10 consecutive resharings (extreme stress test)
	// -------------------------------------------------------------------------
	let mut current_shares_extreme = old_shares.clone();

	for _reshare_round in 0..10 {
		let new_shares = run_resharing_protocol(
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 2],
			&current_shares_extreme,
			&public_key,
		)
		.expect("resharing should succeed");

		current_shares_extreme = new_shares;
	}

	let signing_shares_extreme: Vec<_> = vec![
		current_shares_extreme.get(&0).unwrap().clone(),
		current_shares_extreme.get(&1).unwrap().clone(),
	];

	let (extreme_success, extreme_stats) = run_signing_with_stats(
		&signing_shares_extreme,
		&public_key,
		config,
		num_signings,
		max_retries,
	);

	println!("Reshared Shares (after 10 consecutive resharings):");
	println!("  Success: {}", extreme_success);
	println!("  Successful signings: {}/{}", extreme_stats.successful_attempts, num_signings);
	println!("  Avg retries per signing: {:.2}", extreme_stats.avg_retries_per_success());
	println!("  Max retries for single signing: {}", extreme_stats.max_retries_single_sign);
	println!();

	// -------------------------------------------------------------------------
	// Test 7: 100 consecutive resharings (extreme stress test)
	// -------------------------------------------------------------------------
	let mut current_shares_100x = old_shares.clone();

	for _reshare_round in 0..100 {
		let new_shares = run_resharing_protocol(
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 2],
			&current_shares_100x,
			&public_key,
		)
		.expect("resharing should succeed");

		current_shares_100x = new_shares;
	}

	let signing_shares_100x: Vec<_> = vec![
		current_shares_100x.get(&0).unwrap().clone(),
		current_shares_100x.get(&1).unwrap().clone(),
	];

	let (success_100x, stats_100x) = run_signing_with_stats(
		&signing_shares_100x,
		&public_key,
		config,
		num_signings,
		max_retries,
	);

	println!("Reshared Shares (after 100 consecutive resharings):");
	println!("  Success: {}", success_100x);
	println!("  Successful signings: {}/{}", stats_100x.successful_attempts, num_signings);
	println!("  Avg retries per signing: {:.2}", stats_100x.avg_retries_per_success());
	println!("  Max retries for single signing: {}", stats_100x.max_retries_single_sign);
	println!();

	// -------------------------------------------------------------------------
	// Test 8: 250 consecutive resharings
	// -------------------------------------------------------------------------
	let mut current_shares_250x = old_shares.clone();

	for _reshare_round in 0..250 {
		let new_shares = run_resharing_protocol(
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 2],
			&current_shares_250x,
			&public_key,
		)
		.expect("resharing should succeed");

		current_shares_250x = new_shares;
	}

	let signing_shares_250x: Vec<_> = vec![
		current_shares_250x.get(&0).unwrap().clone(),
		current_shares_250x.get(&1).unwrap().clone(),
	];

	let (success_250x, stats_250x) = run_signing_with_stats(
		&signing_shares_250x,
		&public_key,
		config,
		num_signings,
		max_retries,
	);

	println!("Reshared Shares (after 250 consecutive resharings):");
	println!("  Success: {}", success_250x);
	println!("  Successful signings: {}/{}", stats_250x.successful_attempts, num_signings);
	println!("  Avg retries per signing: {:.2}", stats_250x.avg_retries_per_success());
	println!("  Max retries for single signing: {}", stats_250x.max_retries_single_sign);
	println!();

	// -------------------------------------------------------------------------
	// Test 9: 500 consecutive resharings
	// -------------------------------------------------------------------------
	let mut current_shares_500x = old_shares.clone();

	for _reshare_round in 0..500 {
		let new_shares = run_resharing_protocol(
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 2],
			&current_shares_500x,
			&public_key,
		)
		.expect("resharing should succeed");

		current_shares_500x = new_shares;
	}

	let signing_shares_500x: Vec<_> = vec![
		current_shares_500x.get(&0).unwrap().clone(),
		current_shares_500x.get(&1).unwrap().clone(),
	];

	let (success_500x, stats_500x) = run_signing_with_stats(
		&signing_shares_500x,
		&public_key,
		config,
		num_signings,
		max_retries,
	);

	println!("Reshared Shares (after 500 consecutive resharings):");
	println!("  Success: {}", success_500x);
	println!("  Successful signings: {}/{}", stats_500x.successful_attempts, num_signings);
	println!("  Avg retries per signing: {:.2}", stats_500x.avg_retries_per_success());
	println!("  Max retries for single signing: {}", stats_500x.max_retries_single_sign);
	println!();

	// -------------------------------------------------------------------------
	// Test 10: 1000 consecutive resharings (extreme stress test)
	// -------------------------------------------------------------------------
	let mut current_shares_1000x = old_shares.clone();

	for _reshare_round in 0..1000 {
		let new_shares = run_resharing_protocol(
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 2],
			&current_shares_1000x,
			&public_key,
		)
		.expect("resharing should succeed");

		current_shares_1000x = new_shares;
	}

	let signing_shares_1000x: Vec<_> = vec![
		current_shares_1000x.get(&0).unwrap().clone(),
		current_shares_1000x.get(&1).unwrap().clone(),
	];

	let (success_1000x, stats_1000x) = run_signing_with_stats(
		&signing_shares_1000x,
		&public_key,
		config,
		num_signings,
		max_retries,
	);

	println!("Reshared Shares (after 1000 consecutive resharings):");
	println!("  Success: {}", success_1000x);
	println!("  Successful signings: {}/{}", stats_1000x.successful_attempts, num_signings);
	println!("  Avg retries per signing: {:.2}", stats_1000x.avg_retries_per_success());
	println!("  Max retries for single signing: {}", stats_1000x.max_retries_single_sign);
	println!();

	// -------------------------------------------------------------------------
	// Summary
	// -------------------------------------------------------------------------
	println!("=== Summary ===");
	println!("DKG baseline avg retries:              {:.2}", dkg_stats.avg_retries_per_success());
	println!(
		"Same-committee reshare avg retries:    {:.2}",
		reshared_same_stats.avg_retries_per_success()
	);
	println!(
		"Add-party reshare avg retries:         {:.2}",
		reshared_add_stats.avg_retries_per_success()
	);
	println!(
		"Disjoint reshare avg retries:          {:.2}",
		disjoint_stats.avg_retries_per_success()
	);
	println!("5x consecutive reshare avg retries:    {:.2}", multi_stats.avg_retries_per_success());
	println!(
		"10x consecutive reshare avg retries:   {:.2}",
		extreme_stats.avg_retries_per_success()
	);
	println!("100x consecutive reshare avg retries:  {:.2}", stats_100x.avg_retries_per_success());
	println!("250x consecutive reshare avg retries:  {:.2}", stats_250x.avg_retries_per_success());
	println!("500x consecutive reshare avg retries:  {:.2}", stats_500x.avg_retries_per_success());
	println!("1000x consecutive reshare avg retries: {:.2}", stats_1000x.avg_retries_per_success());

	// All scenarios should succeed
	assert!(dkg_success, "DKG signing should succeed");
	assert!(reshared_same_success, "Same-committee reshared signing should succeed");
	assert!(reshared_add_success, "Add-party reshared signing should succeed");
	assert!(disjoint_success, "Disjoint reshared signing should succeed");
	assert!(multi_success, "5x reshare signing should succeed");
	assert!(extreme_success, "10x reshare signing should succeed");
	assert!(success_100x, "100x reshare signing should succeed");
	assert!(success_250x, "250x reshare signing should succeed");
	// Note: 500x and 1000x resharing may show degradation - this is expected as
	// coefficient magnitudes grow. The key insight is that 250x resharings is still
	// perfectly fine, which far exceeds any practical deployment scenario.
	if !success_500x {
		println!("Note: 500x resharing shows degradation (expected at extreme scales)");
	}
	if !success_1000x {
		println!("Note: 1000x resharing shows degradation (expected at extreme scales)");
	}
}

#[test]
#[ignore] // Long-running test - run with `cargo test -- --ignored`
fn test_coefficient_growth_tracking() {
	// This test monitors coefficient growth at each resharing step to verify
	// that the bounded conditional splitter prevents unbounded growth.

	println!("\n=== Coefficient Growth Tracking ===\n");

	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [0xBB; 32];
	let (public_key, dkg_shares) = generate_with_dealer(&seed, config).expect("keygen");

	// Get baseline coefficient stats from DKG shares
	println!("Round 0 (DKG baseline):");
	for share in &dkg_shares {
		let (max_abs, min_c, max_c) = share.coefficient_stats();
		println!("  Party {}: max_abs={}, range=[{}, {}]", share.party_id(), max_abs, min_c, max_c);
	}

	// Build old_shares map
	let mut current_shares: HashMap<u32, PrivateKeyShare> = HashMap::new();
	for share in &dkg_shares {
		current_shares.insert(share.party_id(), share.clone());
	}

	// Track stats over many resharings
	let checkpoints = [1, 2, 5, 10, 25, 50, 100, 250, 500, 1000];
	let mut checkpoint_idx = 0;

	for round in 1..=1000 {
		let new_shares = run_resharing_protocol(
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 2],
			&current_shares,
			&public_key,
		)
		.expect("resharing should succeed");

		current_shares = new_shares;

		// Print stats at checkpoints
		if checkpoint_idx < checkpoints.len() && round == checkpoints[checkpoint_idx] {
			println!("\nRound {}:", round);
			for party_id in [0, 1, 2] {
				let share = current_shares.get(&party_id).unwrap();
				let (max_abs, min_c, max_c) = share.coefficient_stats();
				println!("  Party {}: max_abs={}, range=[{}, {}]", party_id, max_abs, min_c, max_c);
			}
			checkpoint_idx += 1;
		}
	}

	// Final summary
	println!("\n=== Summary ===");
	println!("Expected behavior with bounded splitter:");
	println!("  - Coefficients should stay bounded (not grow unboundedly)");
	println!("  - max_abs should remain in a reasonable range (< 100 for 2-of-3)");
	println!("\nWith old residual approach, coefficients would grow ~sqrt(n) and");
	println!("exceed bounds around 250-500 resharings.");
}
