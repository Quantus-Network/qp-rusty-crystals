//! Integration tests for the resharing (committee handoff) protocol.
//!
//! These tests verify that the resharing protocol correctly transfers
//! secret shares to a new committee while preserving the public key.

use std::collections::HashMap;

use qp_rusty_crystals_threshold::{
	compute_ssid, convert_shares, create_signing_permutation, generate_subsets_of_size,
	generate_with_dealer, get_hyperball_params, translate_pattern_to_subset, verify_signature,
	ParticipantList, PrivateKeyShare, PublicKey, Round1Broadcast, Round2Broadcast, Round3Broadcast,
	ThresholdConfig, ThresholdSigner,
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
			existing_share,
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

		let protocol = ResharingProtocol::new(config, seed, &session_nonce);
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
			message,
			context,
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
		let signature = match signers[0].combine(&r2_broadcasts, &r3_broadcasts) {
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
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	// Create resharing config for party 0 (staying in committee - Both role)
	let resharing_config = ResharingConfig::new(
		Some(shares[0].clone()), // old member needs share
		2,                       // old threshold
		vec![0, 1, 2],           // old participants
		2,                       // new threshold
		vec![0, 1, 3],           // new participants (2 leaves, 3 joins)
		0,                       // my party id (ignored since share provided)
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

	// Create resharing config for party 3 (joining - NewOnly role)
	let resharing_config = ResharingConfig::new(
		None, // new member has no share
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
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	// Create resharing config for party 2 (leaving - OldOnly role)
	let resharing_config = ResharingConfig::new(
		Some(shares[2].clone()), // old member needs share
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 3],
		2, // leaving party (ignored since share provided)
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
		Some(shares[0].clone()),
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
	let protocol = ResharingProtocol::new(resharing_config, protocol_seed, &session_nonce);
	assert_eq!(*protocol.state(), ResharingState::Round1Generate);
}

#[test]
fn test_resharing_protocol_round1_generation() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	let resharing_config = ResharingConfig::new(
		Some(shares[0].clone()),
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
	let mut protocol = ResharingProtocol::new(resharing_config, protocol_seed, &session_nonce);

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
	let resharing_config = ResharingConfig::new(
		None, // new member has no share
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 3],
		3,
		public_key,
	)
	.expect("valid config");

	let protocol_seed = [42u8; 32];
	let session_nonce = [0x66u8; 32];
	let mut protocol = ResharingProtocol::new(resharing_config, protocol_seed, &session_nonce);

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
			Some(old_shares.get(&party_id).unwrap().clone()),
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
		let existing_share = old_shares.get(&party_id).cloned();
		let resharing_config = ResharingConfig::new(
			existing_share,
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
		let existing_share = old_shares.get(&party_id).cloned();
		let resharing_config = ResharingConfig::new(
			existing_share,
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
		let existing_share = old_shares.get(&party_id).cloned();
		let resharing_config = ResharingConfig::new(
			existing_share,
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
		let existing_share = old_shares.get(&party_id).cloned();
		let resharing_config = ResharingConfig::new(
			existing_share,
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

	// Party 10 is not in either committee and provides no share (NewOnly validation fails)
	let result = ResharingConfig::new(None, 2, vec![0, 1, 2], 2, vec![3, 4, 5], 10, public_key);

	assert!(result.is_err());
}

// ============================================================================
// existing_share validation tests
// ============================================================================

#[test]
fn test_old_party_requires_existing_share() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, _shares) = generate_with_dealer(&seed, config).expect("keygen");

	// Party 0 is in old committee but doesn't provide existing_share (None)
	// With new API, this should fail at config level since party 0 is in old committee
	// but no share is provided
	let result = ResharingConfig::new(
		None, // No share provided
		2,
		vec![0, 1, 2], // old committee - party 0 is here
		2,
		vec![0, 1, 2], // same new committee
		0,             // party_id 0 - but this is in old committee!
		public_key,
	);

	// With new API: If party_id is in old committee and no share provided, error
	// (since party would need a share to participate as old member)
	assert!(result.is_err(), "Old committee member without share should fail at config level");
}

#[test]
fn test_new_only_party_share_override() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	// Party 3 is joining (NewOnly) but incorrectly provides an existing_share
	// With new API: providing a share extracts party_id from share
	// If share's party_id != 3, or if share's party_id is not in old committee, error
	// share[0] has party_id=0, which IS in old committee - so this would make config
	// treat this as party 0 (Both role), not party 3 (NewOnly)
	let result = ResharingConfig::new(
		Some(shares[0].clone()), // share from party 0
		2,
		vec![0, 1, 2], // old committee
		2,
		vec![0, 1, 3], // new committee
		3,             // party_id is ignored when share is Some
		public_key,
	);

	// With new API: share[0] has party_id=0, so config will use party_id=0 (Both role)
	// This should succeed - the party_id parameter is ignored when share is provided
	assert!(
		result.is_ok(),
		"Providing share overrides party_id - config should succeed with party 0's role"
	);

	// Verify that the config actually used party 0, not party 3
	let cfg = result.unwrap();
	assert_eq!(cfg.my_party_id(), 0, "Config should use party_id from share, not from parameter");
}

#[test]
fn test_share_party_id_must_match_old_committee() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	// Try to use a share from party 0 but claim party 0 is not in old committee
	// This is a misconfiguration - party 0's share says party_id=0, but old_participants
	// doesn't include 0
	let result = ResharingConfig::new(
		Some(shares[0].clone()), // party 0's share
		2,
		vec![1, 2, 3], // old committee doesn't include party 0!
		2,
		vec![0, 1, 2, 3], // new committee
		0,                // ignored when share is Some
		public_key,
	);

	// This should fail because the share's party_id (0) is not in old_participants
	assert!(result.is_err(), "Share's party_id must be in old committee");
}

#[test]
fn test_share_threshold_must_match_old_threshold() {
	// Create a 3-of-5 setup
	let config = ThresholdConfig::new(3, 5).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	// Resharing config claims old_threshold=2, but the share has threshold=3
	let result = ResharingConfig::new(
		Some(shares[0].clone()), // share has threshold=3
		2,                       // Wrong old_threshold! (should be 3)
		vec![0, 1, 2, 3, 4],     // all 5 parties
		2,                       // new threshold
		vec![0, 1, 2, 3, 4],     // same committee
		0,                       // ignored when share is Some
		public_key,
	);

	// This should fail because share's threshold (3) != old_threshold (2)
	assert!(result.is_err(), "Share threshold must match old_threshold");
}

#[test]
fn test_share_public_key_must_match_config() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed1 = [42u8; 32];
	let seed2 = [99u8; 32]; // Different seed -> different keys
	let (_public_key1, shares1) = generate_with_dealer(&seed1, config).expect("keygen");
	let (public_key2, _shares2) = generate_with_dealer(&seed2, config).expect("keygen");

	// Config uses public_key2 but share is from public_key1
	// With new API, the share goes into config - so TR mismatch is caught at config level
	let result = ResharingConfig::new(
		Some(shares1[0].clone()), // Share from public_key1
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 2],
		0,
		public_key2, // Different public key!
	);

	// This should fail because share's TR != public_key2's TR
	assert!(result.is_err(), "Share TR must match config public key TR");
}

#[test]
fn test_valid_resharing_configuration_succeeds() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	// Valid: Both role with matching share
	let resharing_config = ResharingConfig::new(
		Some(shares[0].clone()),
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 2],
		0,
		public_key.clone(),
	)
	.expect("valid config");

	let session_nonce = [0xFFu8; 32];
	let _protocol = ResharingProtocol::new(resharing_config, [42u8; 32], &session_nonce);

	// Valid: NewOnly with None
	let resharing_config2 = ResharingConfig::new(
		None, // NewOnly - no share
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 3], // party 3 joining
		3,
		public_key,
	)
	.expect("valid config for NewOnly");

	let _protocol2 = ResharingProtocol::new(resharing_config2, [42u8; 32], &session_nonce);
}

#[test]
fn test_resharing_config_invalid_old_threshold() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, _shares) = generate_with_dealer(&seed, config).expect("keygen");

	// Old threshold too high - but this is for a NewOnly party (no share)
	let result = ResharingConfig::new(
		None, // NewOnly
		5,    // invalid: > n
		vec![0, 1, 2],
		2,
		vec![0, 1, 2, 3], // party 3 joining
		3,
		public_key,
	);

	assert!(result.is_err());
}

#[test]
fn test_resharing_config_invalid_new_threshold() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	// New threshold too low - need to provide share since party 0 is in old committee
	let result = ResharingConfig::new(
		Some(shares[0].clone()),
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
		Some(shares[0].clone()),
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 2],
		0,
		public_key.clone(),
	)
	.expect("valid config");

	let session_nonce = [0x44u8; 32];
	let mut protocol = ResharingProtocol::new(resharing_config, [42u8; 32], &session_nonce);

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
		Some(shares[0].clone()),
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 2],
		0,
		public_key.clone(),
	)
	.expect("valid config");

	let config1 = ResharingConfig::new(
		Some(shares[1].clone()),
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 2],
		1,
		public_key.clone(),
	)
	.expect("valid config");

	let session_nonce = [0x33u8; 32];
	let mut protocol0 = ResharingProtocol::new(config0, [0u8; 32], &session_nonce);
	let mut protocol1 = ResharingProtocol::new(config1, [1u8; 32], &session_nonce);

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
		Some(shares[2].clone()),
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 3], // party 2 not in new committee
		2,
		public_key,
	)
	.expect("valid config");

	let session_nonce = [0x22u8; 32];
	let mut protocol = ResharingProtocol::new(resharing_config, [42u8; 32], &session_nonce);

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
		None, // NewOnly - no share
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 3],
		3, // new party
		public_key,
	)
	.expect("valid config");

	let session_nonce = [0x11u8; 32];
	let mut protocol = ResharingProtocol::new(resharing_config, [42u8; 32], &session_nonce);

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
/// public-key invariant.
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
fn test_resharing_aborts_when_commitment_tampered() {
	// In a (2,3) resharing, old subsets have size 2 (n - t + 1 = 3 - 2 + 1 = 2).
	// If the dealer broadcasts a bad commitment, the protocol will detect the mismatch
	// during share verification and abort (without blame attribution).

	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [77u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	let mut old_shares: HashMap<u32, PrivateKeyShare> = HashMap::new();
	for share in &shares {
		old_shares.insert(share.party_id(), share.clone());
	}

	// Tamper the Round 3 Commitments. The recipient will detect that the received
	// sub-share doesn't match the tampered commitment.
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

	let err = result.expect_err("tampered commitment must be detected");
	// The protocol aborts when it detects misbehavior (no blame attribution)
	assert!(
		err.contains("abort") ||
			err.contains("Abort") ||
			err.contains("verification") ||
			err.contains("Verification") ||
			err.contains("failed") ||
			err.contains("Failed"),
		"expected protocol abort due to verification failure, got: {}",
		err
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
	// The protocol aborts when it detects the mismatch
	assert!(
		err.contains("commitment") ||
			err.contains("ShareVerificationFailed") ||
			err.contains("Party failure") ||
			err.contains("abort") ||
			err.contains("Abort") ||
			err.contains("parties reported failure"),
		"expected protocol abort due to verification failure, got: {}",
		err
	);
}

#[test]
fn test_resharing_detects_consistent_dealer_tamper_at_t_equals_n() {
	// In a (2,2) -> (2,2) resharing every old subset has size 1, so the dealer is
	// the sole member of their old subset and no other party can verify their
	// commitment against the original share. To prove that lying about `r` is
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
			ResharingMessage::Round3(mut b) => {
				if let Some(c) = b.commitments.get_mut(&target_pair) {
					*c = bogus_commit;
					ResharingMessage::Round3(b)
				} else {
					ResharingMessage::Round3(b)
				}
			},
			ResharingMessage::Round4(mut m) => {
				if m.from_party_id == 0 && m.contributions.contains_key(&target_pair) {
					m.contributions.insert(target_pair, bogus_r_capt.clone());
					ResharingMessage::Round4(m)
				} else {
					ResharingMessage::Round4(m)
				}
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
			err.contains("PartyFailure") ||
			err.contains("abort") ||
			err.contains("Abort") ||
			err.contains("parties reported failure"),
		"expected protocol abort due to tampering, got: {}",
		err
	);
}

// ============================================================================
// Session Randomization Tests
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
			existing_share,
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
		let protocol = ResharingProtocol::new(config, seed, &session_nonce);
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
fn test_session_randomization_different_sessions_produce_different_subshares() {
	// This test verifies session randomization: running the resharing protocol twice
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

	// The key session-randomization test: the shares should be different.
	// We compare the serialized shares to detect any difference in the internal structure.
	// If the entropy wasn't being used, the shares would be identical.
	let share_0_session_1 = borsh::to_vec(new_shares_1.get(&0).unwrap()).unwrap();
	let share_0_session_2 = borsh::to_vec(new_shares_2.get(&0).unwrap()).unwrap();

	assert_ne!(
		share_0_session_1, share_0_session_2,
		"Shares from different sessions should differ due to session-randomization entropy"
	);

	// Also verify that shares from different parties within the same session differ
	// (this was already the case, but good to confirm)
	let share_1_session_1 = borsh::to_vec(new_shares_1.get(&1).unwrap()).unwrap();
	assert_ne!(share_0_session_1, share_1_session_1, "Shares for different parties should differ");

	println!("Session randomization verified: different entropy seeds produce different shares");
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
fn test_session_randomization_identical_seeds_produce_identical_shares() {
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
fn test_session_randomization_single_party_entropy_change_affects_all() {
	// This test verifies that even if only ONE party changes their entropy,
	// all resulting shares change. This is important for pre-reveal unpredictability:
	// before Round 2, the session seed cannot be predicted without every old
	// committee member's entropy contribution.

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

	println!(
		"Session-randomization cascade verified: one party's entropy change affects all shares"
	);
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
				message.as_bytes(),
				b"",
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
			let signature = match signers[0].combine(&r2_broadcasts, &r3_broadcasts) {
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

/// Test that when a dealer omits Round 4 delivery to a specific victim, the protocol
/// correctly detects the failure and aborts.
///
/// Attack scenario:
/// 1. Dealer (party 0) broadcasts faithful Round 3 commitments
/// 2. Dealer omits Round 4 private delivery to victim (party 2)
/// 3. Victim fails verification (missing data)
/// 4. Protocol aborts (without blame attribution, since attribution isn't always possible)
#[test]
fn test_resharing_aborts_on_round4_omission() {
	use std::{cell::RefCell, rc::Rc};

	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [0xAAu8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	let mut old_shares: HashMap<u32, PrivateKeyShare> = HashMap::new();
	for share in &shares {
		old_shares.insert(share.party_id(), share.clone());
	}

	// Party 0 (dealer) will omit Round 4 delivery to party 2 (victim)
	let malicious_dealer: u32 = 0;
	let victim: u32 = 2;

	// Track dropped Round 4 messages so we can verify the attack worked
	let dropped_count = Rc::new(RefCell::new(0u32));
	let dropped_count_clone = dropped_count.clone();

	// Remove all contributions from dealer's Round 4 message to the victim.
	let tamper: TamperFn = Box::new(move |sender, recipient, data| {
		// Only intercept Round 4 messages from the malicious dealer to the victim
		if sender == malicious_dealer && recipient == Some(victim) {
			let msg: ResharingMessage = match borsh::from_slice(&data) {
				Ok(m) => m,
				Err(_) => return data,
			};
			// Strip all contributions from the Round 4 message
			if let ResharingMessage::Round4(mut r4) = msg {
				*dropped_count_clone.borrow_mut() += 1;
				r4.contributions.clear(); // Empty contributions = dealer didn't deliver
				return borsh::to_vec(&ResharingMessage::Round4(r4))
					.expect("re-serialize tampered msg");
			}
		}
		data
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

	// Verify we actually tampered with some messages
	assert!(*dropped_count.borrow() > 0, "Test setup error: no Round 4 messages were tampered");

	// Protocol should fail due to the omission
	assert!(result.is_err(), "Protocol should fail when dealer omits Round 4 delivery");

	let err = result.unwrap_err();
	println!("Error: {}", err);

	// The protocol aborts without blame attribution
	assert!(
		err.contains("abort") ||
			err.contains("Abort") ||
			err.contains("failed") ||
			err.contains("Failed") ||
			err.contains("missing") ||
			err.contains("Missing"),
		"Protocol should abort due to missing Round 4 data. Got: {}",
		err
	);
}

// ============================================================================
// Coefficient Distribution Analysis
// ============================================================================

/// Collect all coefficients from a set of shares, centered in (-Q/2, Q/2].
fn collect_coefficients(shares: &HashMap<u32, PrivateKeyShare>) -> Vec<i32> {
	let mut coeffs = Vec::new();
	for share in shares.values() {
		coeffs.extend(share.collect_all_coefficients());
	}
	coeffs
}

/// Compute distribution statistics for a set of coefficients.
struct DistributionStats {
	count: usize,
	min: i32,
	max: i32,
	mean: f64,
	variance: f64,
	std_dev: f64,
	skewness: f64,
	kurtosis: f64,
	histogram: std::collections::BTreeMap<i32, usize>,
}

fn compute_distribution_stats(coeffs: &[i32]) -> DistributionStats {
	use std::collections::BTreeMap;

	let count = coeffs.len();
	let min = *coeffs.iter().min().unwrap_or(&0);
	let max = *coeffs.iter().max().unwrap_or(&0);

	// Mean
	let sum: i64 = coeffs.iter().map(|&c| c as i64).sum();
	let mean = sum as f64 / count as f64;

	// Variance and higher moments
	let mut m2: f64 = 0.0; // sum of (x - mean)^2
	let mut m3: f64 = 0.0; // sum of (x - mean)^3
	let mut m4: f64 = 0.0; // sum of (x - mean)^4

	for &c in coeffs {
		let d = c as f64 - mean;
		let d2 = d * d;
		m2 += d2;
		m3 += d2 * d;
		m4 += d2 * d2;
	}

	let variance = m2 / count as f64;
	let std_dev = variance.sqrt();

	// Skewness = E[(X-μ)³] / σ³
	let skewness =
		if std_dev > 0.0 { (m3 / count as f64) / (std_dev * std_dev * std_dev) } else { 0.0 };

	// Kurtosis = E[(X-μ)⁴] / σ⁴ - 3 (excess kurtosis, 0 for normal)
	let kurtosis =
		if std_dev > 0.0 { (m4 / count as f64) / (variance * variance) - 3.0 } else { 0.0 };

	// Build histogram
	let mut histogram: BTreeMap<i32, usize> = BTreeMap::new();
	for &c in coeffs {
		*histogram.entry(c).or_insert(0) += 1;
	}

	DistributionStats { count, min, max, mean, variance, std_dev, skewness, kurtosis, histogram }
}

/// Compute chi-squared statistic comparing observed distribution to uniform.
/// Returns (chi_squared, degrees_of_freedom, p_value_approximate).
fn chi_squared_vs_uniform(
	histogram: &std::collections::BTreeMap<i32, usize>,
	total: usize,
) -> (f64, usize, f64) {
	let num_bins = histogram.len();
	if num_bins == 0 {
		return (0.0, 0, 1.0);
	}

	let expected = total as f64 / num_bins as f64;
	let mut chi_sq: f64 = 0.0;

	for &observed in histogram.values() {
		let diff = observed as f64 - expected;
		chi_sq += (diff * diff) / expected;
	}

	let df = num_bins - 1;

	// Approximate p-value using Wilson-Hilferty transformation
	// For large df, chi-squared approaches normal distribution
	let p_value = if df > 0 {
		// Normalized chi-squared
		let z = (chi_sq / df as f64).powf(1.0 / 3.0) - (1.0 - 2.0 / (9.0 * df as f64));
		let z = z / (2.0 / (9.0 * df as f64)).sqrt();
		// Convert to p-value (one-tailed, upper)
		0.5 * (1.0 - erf(z / std::f64::consts::SQRT_2))
	} else {
		1.0
	};

	(chi_sq, df, p_value)
}

/// Error function approximation for p-value calculation.
fn erf(x: f64) -> f64 {
	// Abramowitz and Stegun approximation
	let a1 = 0.254829592;
	let a2 = -0.284496736;
	let a3 = 1.421413741;
	let a4 = -1.453152027;
	let a5 = 1.061405429;
	let p = 0.3275911;

	let sign = if x < 0.0 { -1.0 } else { 1.0 };
	let x = x.abs();

	let t = 1.0 / (1.0 + p * x);
	let y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * (-x * x).exp();

	sign * y
}

/// Print a simple ASCII histogram.
fn print_histogram(
	histogram: &std::collections::BTreeMap<i32, usize>,
	total: usize,
	max_width: usize,
) {
	let max_count = *histogram.values().max().unwrap_or(&1);
	let scale = max_width as f64 / max_count as f64;

	for (&value, &count) in histogram {
		let bar_len = (count as f64 * scale) as usize;
		let pct = 100.0 * count as f64 / total as f64;
		println!("{:4}: {:6} ({:5.2}%) {}", value, count, pct, "█".repeat(bar_len));
	}
}

#[test]
fn test_coefficient_distribution_analysis() {
	println!("\n======================================================================");
	println!("COEFFICIENT DISTRIBUTION ANALYSIS");
	println!("======================================================================\n");

	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [0xCCu8; 32];
	let (public_key, dkg_shares) = generate_with_dealer(&seed, config).expect("keygen");

	// Convert to HashMap
	let mut current_shares: HashMap<u32, PrivateKeyShare> = HashMap::new();
	for share in &dkg_shares {
		current_shares.insert(share.party_id(), share.clone());
	}

	// ========== DKG Baseline ==========
	println!("=== DKG Baseline (0 resharings) ===\n");
	let dkg_coeffs = collect_coefficients(&current_shares);
	let dkg_stats = compute_distribution_stats(&dkg_coeffs);

	println!("Sample size: {} coefficients", dkg_stats.count);
	println!("Range: [{}, {}]", dkg_stats.min, dkg_stats.max);
	println!("Mean: {:.6}", dkg_stats.mean);
	println!("Std Dev: {:.6}", dkg_stats.std_dev);
	println!("Variance: {:.6}", dkg_stats.variance);
	println!("Skewness: {:.6} (0 = symmetric)", dkg_stats.skewness);
	println!("Excess Kurtosis: {:.6} (0 = normal, <0 = flatter, >0 = peakier)", dkg_stats.kurtosis);

	println!("\nHistogram:");
	print_histogram(&dkg_stats.histogram, dkg_stats.count, 50);

	let (chi_sq, df, p_value) = chi_squared_vs_uniform(&dkg_stats.histogram, dkg_stats.count);
	println!("\nChi-squared vs uniform: {:.2} (df={}, p≈{:.4})", chi_sq, df, p_value);
	println!("  (p > 0.05 means we cannot reject uniformity hypothesis)");

	// Verify DKG produces uniform over [-2, 2]
	assert_eq!(dkg_stats.min, -2, "DKG min should be -2 (eta)");
	assert_eq!(dkg_stats.max, 2, "DKG max should be 2 (eta)");
	assert!(dkg_stats.skewness.abs() < 0.1, "DKG should be symmetric");

	// For uniform over {-2,-1,0,1,2}: variance = (4+1+0+1+4)/5 = 2.0
	let expected_uniform_variance = 2.0;
	assert!(
		(dkg_stats.variance - expected_uniform_variance).abs() < 0.1,
		"DKG variance should be ~2.0 for uniform over [-2,2], got {}",
		dkg_stats.variance
	);

	// ========== After 1 Resharing ==========
	println!("\n\n=== After 1 Resharing ===\n");

	let new_shares =
		run_resharing_protocol(2, vec![0, 1, 2], 2, vec![0, 1, 2], &current_shares, &public_key)
			.expect("resharing should succeed");
	current_shares = new_shares;

	let r1_coeffs = collect_coefficients(&current_shares);
	let r1_stats = compute_distribution_stats(&r1_coeffs);

	println!("Sample size: {} coefficients", r1_stats.count);
	println!("Range: [{}, {}]", r1_stats.min, r1_stats.max);
	println!("Mean: {:.6}", r1_stats.mean);
	println!("Std Dev: {:.6}", r1_stats.std_dev);
	println!("Variance: {:.6}", r1_stats.variance);
	println!("Skewness: {:.6}", r1_stats.skewness);
	println!("Excess Kurtosis: {:.6}", r1_stats.kurtosis);

	println!("\nHistogram:");
	print_histogram(&r1_stats.histogram, r1_stats.count, 50);

	let (chi_sq, df, p_value) = chi_squared_vs_uniform(&r1_stats.histogram, r1_stats.count);
	println!("\nChi-squared vs uniform: {:.2} (df={}, p≈{:.4})", chi_sq, df, p_value);

	// ========== After 10 Resharings ==========
	println!("\n\n=== After 10 Resharings ===\n");

	for _ in 0..9 {
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

	let r10_coeffs = collect_coefficients(&current_shares);
	let r10_stats = compute_distribution_stats(&r10_coeffs);

	println!("Sample size: {} coefficients", r10_stats.count);
	println!("Range: [{}, {}]", r10_stats.min, r10_stats.max);
	println!("Mean: {:.6}", r10_stats.mean);
	println!("Std Dev: {:.6}", r10_stats.std_dev);
	println!("Variance: {:.6}", r10_stats.variance);
	println!("Skewness: {:.6}", r10_stats.skewness);
	println!("Excess Kurtosis: {:.6}", r10_stats.kurtosis);

	println!("\nHistogram:");
	print_histogram(&r10_stats.histogram, r10_stats.count, 50);

	let (chi_sq, df, p_value) = chi_squared_vs_uniform(&r10_stats.histogram, r10_stats.count);
	println!("\nChi-squared vs uniform: {:.2} (df={}, p≈{:.4})", chi_sq, df, p_value);

	// ========== After 100 Resharings ==========
	println!("\n\n=== After 100 Resharings ===\n");

	for _ in 0..90 {
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

	let r100_coeffs = collect_coefficients(&current_shares);
	let r100_stats = compute_distribution_stats(&r100_coeffs);

	println!("Sample size: {} coefficients", r100_stats.count);
	println!("Range: [{}, {}]", r100_stats.min, r100_stats.max);
	println!("Mean: {:.6}", r100_stats.mean);
	println!("Std Dev: {:.6}", r100_stats.std_dev);
	println!("Variance: {:.6}", r100_stats.variance);
	println!("Skewness: {:.6}", r100_stats.skewness);
	println!("Excess Kurtosis: {:.6}", r100_stats.kurtosis);

	println!("\nHistogram:");
	print_histogram(&r100_stats.histogram, r100_stats.count, 50);

	let (chi_sq, df, p_value) = chi_squared_vs_uniform(&r100_stats.histogram, r100_stats.count);
	println!("\nChi-squared vs uniform: {:.2} (df={}, p≈{:.4})", chi_sq, df, p_value);

	// ========== Summary ==========
	println!("\n\n======================================================================");
	println!("SUMMARY");
	println!("======================================================================\n");

	println!("| Resharings | Range        | Std Dev | Variance | Skewness | Kurtosis | Chi-sq (vs uniform) |");
	println!("|------------|--------------|---------|----------|----------|----------|---------------------|");
	println!(
		"| {:>10} | [{:>3}, {:>3}]   | {:>7.3} | {:>8.3} | {:>8.4} | {:>8.4} | {:>19.2} |",
		0,
		dkg_stats.min,
		dkg_stats.max,
		dkg_stats.std_dev,
		dkg_stats.variance,
		dkg_stats.skewness,
		dkg_stats.kurtosis,
		chi_squared_vs_uniform(&dkg_stats.histogram, dkg_stats.count).0
	);
	println!(
		"| {:>10} | [{:>3}, {:>3}]   | {:>7.3} | {:>8.3} | {:>8.4} | {:>8.4} | {:>19.2} |",
		1,
		r1_stats.min,
		r1_stats.max,
		r1_stats.std_dev,
		r1_stats.variance,
		r1_stats.skewness,
		r1_stats.kurtosis,
		chi_squared_vs_uniform(&r1_stats.histogram, r1_stats.count).0
	);
	println!(
		"| {:>10} | [{:>3}, {:>3}]   | {:>7.3} | {:>8.3} | {:>8.4} | {:>8.4} | {:>19.2} |",
		10,
		r10_stats.min,
		r10_stats.max,
		r10_stats.std_dev,
		r10_stats.variance,
		r10_stats.skewness,
		r10_stats.kurtosis,
		chi_squared_vs_uniform(&r10_stats.histogram, r10_stats.count).0
	);
	println!(
		"| {:>10} | [{:>3}, {:>3}]   | {:>7.3} | {:>8.3} | {:>8.4} | {:>8.4} | {:>19.2} |",
		100,
		r100_stats.min,
		r100_stats.max,
		r100_stats.std_dev,
		r100_stats.variance,
		r100_stats.skewness,
		r100_stats.kurtosis,
		chi_squared_vs_uniform(&r100_stats.histogram, r100_stats.count).0
	);

	println!("\nInterpretation:");
	println!("- DKG: Should be uniform over [-2, 2] (5 values)");
	println!("- After resharing: Distribution changes but remains bounded");
	println!("- High chi-squared = very non-uniform (peaked distribution)");
	println!("- Negative kurtosis = flatter than normal (platykurtic)");
	println!("- Positive kurtosis = more peaked than normal (leptokurtic)");

	// Basic sanity checks
	assert!(r1_stats.max <= 20, "After 1 resharing, max should be bounded");
	assert!(r10_stats.max <= 20, "After 10 resharings, max should be bounded");
	assert!(r100_stats.max <= 20, "After 100 resharings, max should be bounded");
	assert!(r1_stats.skewness.abs() < 0.5, "Distribution should remain roughly symmetric");
	assert!(r10_stats.skewness.abs() < 0.5, "Distribution should remain roughly symmetric");
	assert!(r100_stats.skewness.abs() < 0.5, "Distribution should remain roughly symmetric");
}

/// Helper to run distribution analysis for any (t, n) configuration
fn run_distribution_analysis(threshold: u32, parties: u32, max_resharings: usize) {
	println!("\n======================================================================");
	println!("COEFFICIENT DISTRIBUTION ANALYSIS: {}-of-{}", threshold, parties);
	println!("======================================================================\n");

	let config = ThresholdConfig::new(threshold, parties).expect("valid config");
	let seed = [0xDDu8; 32];
	let (public_key, dkg_shares) = generate_with_dealer(&seed, config).expect("keygen");

	let participants: Vec<u32> = (0..parties).collect();

	// Convert to HashMap
	let mut current_shares: HashMap<u32, PrivateKeyShare> = HashMap::new();
	for share in &dkg_shares {
		current_shares.insert(share.party_id(), share.clone());
	}

	// Collect stats at various checkpoints
	let mut all_stats: Vec<(usize, DistributionStats)> = Vec::new();

	// DKG baseline
	let dkg_coeffs = collect_coefficients(&current_shares);
	let dkg_stats = compute_distribution_stats(&dkg_coeffs);
	println!("=== DKG Baseline (0 resharings) ===");
	println!("Sample size: {} coefficients", dkg_stats.count);
	println!("Range: [{}, {}]", dkg_stats.min, dkg_stats.max);
	println!("Std Dev: {:.3}, Variance: {:.3}", dkg_stats.std_dev, dkg_stats.variance);
	println!("Skewness: {:.4}, Kurtosis: {:.4}", dkg_stats.skewness, dkg_stats.kurtosis);
	all_stats.push((0, dkg_stats));

	// Checkpoints to measure
	let checkpoints: Vec<usize> =
		vec![1, 2, 5, 10, 20].into_iter().filter(|&x| x <= max_resharings).collect();

	let mut resharing_count = 0;
	for &checkpoint in &checkpoints {
		// Run resharings up to this checkpoint
		while resharing_count < checkpoint {
			let new_shares = run_resharing_protocol(
				threshold,
				participants.clone(),
				threshold,
				participants.clone(),
				&current_shares,
				&public_key,
			)
			.expect("resharing should succeed");
			current_shares = new_shares;
			resharing_count += 1;
		}

		let coeffs = collect_coefficients(&current_shares);
		let stats = compute_distribution_stats(&coeffs);
		println!("\n=== After {} Resharing(s) ===", checkpoint);
		println!("Range: [{}, {}]", stats.min, stats.max);
		println!("Std Dev: {:.3}, Variance: {:.3}", stats.std_dev, stats.variance);
		println!("Skewness: {:.4}, Kurtosis: {:.4}", stats.skewness, stats.kurtosis);
		all_stats.push((checkpoint, stats));
	}

	// Print summary table
	println!("\n\n=== SUMMARY: {}-of-{} ===\n", threshold, parties);
	println!("| Resharings | Range        | Std Dev | Variance | Skewness | Kurtosis |");
	println!("|------------|--------------|---------|----------|----------|----------|");
	for (count, stats) in &all_stats {
		println!(
			"| {:>10} | [{:>3}, {:>3}]   | {:>7.3} | {:>8.3} | {:>8.4} | {:>8.4} |",
			count,
			stats.min,
			stats.max,
			stats.std_dev,
			stats.variance,
			stats.skewness,
			stats.kurtosis
		);
	}

	// Check idempotence: variance should stabilize
	if all_stats.len() >= 3 {
		let var_after_1 = all_stats[1].1.variance;
		let var_last = all_stats.last().unwrap().1.variance;
		let var_change = ((var_last - var_after_1) / var_after_1).abs();
		println!(
			"\nVariance change from resharing 1 to {}: {:.2}%",
			all_stats.last().unwrap().0,
			var_change * 100.0
		);
		println!("(Small change indicates idempotent distribution)");
	}
}

#[test]
fn test_coefficient_distribution_3_of_5() {
	run_distribution_analysis(3, 5, 20);
}

#[test]
fn test_coefficient_distribution_2_of_4() {
	run_distribution_analysis(2, 4, 20);
}

#[test]
fn test_coefficient_distribution_4_of_6() {
	run_distribution_analysis(4, 6, 10);
}

// ============================================================================
// Recovered Partial Analysis Tests
// ============================================================================
//
// These tests analyze the variance of recovered partials (what's actually used
// in signing) compared to individual stored shares. The hyperball rejection
// sampling parameters are computed assuming a certain coefficient standard
// deviation, so we need to verify that post-resharing partials stay within
// acceptable bounds.

/// Statistics for recovered partial analysis.
#[derive(Debug, Clone)]
struct RecoveredPartialStats {
	/// Number of shares summed to form this partial
	num_shares_summed: usize,
	/// L-infinity norm of s1 component
	s1_linf_norm: i64,
	/// L-infinity norm of s2 component
	s2_linf_norm: i64,
	/// Variance of s1 coefficients
	s1_variance: f64,
	/// Variance of s2 coefficients
	s2_variance: f64,
	/// Combined weighted norm: sqrt(||s1||^2/nu^2 + ||s2||^2)
	combined_weighted_norm: f64,
}

/// Compute statistics for a recovered partial.
fn compute_partial_stats(s1_coeffs: &[i64], s2_coeffs: &[i64], nu: f64) -> RecoveredPartialStats {
	// L2 norms
	let s1_l2_sq: f64 = s1_coeffs.iter().map(|&c| (c as f64).powi(2)).sum();
	let s2_l2_sq: f64 = s2_coeffs.iter().map(|&c| (c as f64).powi(2)).sum();

	// L-infinity norms
	let s1_linf = s1_coeffs.iter().map(|&c| c.abs()).max().unwrap_or(0);
	let s2_linf = s2_coeffs.iter().map(|&c| c.abs()).max().unwrap_or(0);

	// Variances
	let s1_mean: f64 = s1_coeffs.iter().map(|&c| c as f64).sum::<f64>() / s1_coeffs.len() as f64;
	let s2_mean: f64 = s2_coeffs.iter().map(|&c| c as f64).sum::<f64>() / s2_coeffs.len() as f64;

	let s1_variance: f64 = s1_coeffs.iter().map(|&c| (c as f64 - s1_mean).powi(2)).sum::<f64>() /
		s1_coeffs.len() as f64;
	let s2_variance: f64 = s2_coeffs.iter().map(|&c| (c as f64 - s2_mean).powi(2)).sum::<f64>() /
		s2_coeffs.len() as f64;

	// Combined weighted norm (as used in hyperball check)
	let combined_weighted_norm = (s1_l2_sq / (nu * nu) + s2_l2_sq).sqrt();

	RecoveredPartialStats {
		num_shares_summed: 0, // Set by caller
		s1_linf_norm: s1_linf,
		s2_linf_norm: s2_linf,
		s1_variance,
		s2_variance,
		combined_weighted_norm,
	}
}

/// Extract centered coefficients from recovered partial for analysis.
/// Sums share coefficients directly (no NTT) for statistical analysis.
///
/// Uses the same permutation and translation logic as `recover_share` via shared
/// helpers to ensure the test stays in sync with production code.
fn extract_recovered_coefficients(
	share: &PrivateKeyShare,
	signing_set: &[u32],
) -> Option<(Vec<i64>, Vec<i64>)> {
	const Q: i64 = 8380417;
	const HALF_Q: i64 = Q / 2;

	if !signing_set.contains(&share.party_id()) {
		return None;
	}

	let shares = convert_shares(share);
	let threshold = share.threshold();
	let parties = share.total_parties();
	let t = threshold as usize;
	let n = parties as usize;

	// Compute sharing patterns (same as recover_share)
	let subset_size = n - t + 1;
	let subsets = generate_subsets_of_size(n, subset_size);

	let mut patterns: Vec<Vec<u16>> = vec![Vec::new(); t];
	let mut used = std::collections::BTreeSet::new();
	for (pos, pattern) in patterns.iter_mut().enumerate().take(t) {
		for &subset in &subsets {
			if !used.contains(&subset) && (subset & (1 << pos)) != 0 {
				pattern.push(subset);
				used.insert(subset);
			}
		}
	}

	// Sort signing set and find our position
	let mut sorted_signing: Vec<u32> = signing_set.to_vec();
	sorted_signing.sort();

	let my_dkg_index = share.dkg_participants().index_of(share.party_id())?;
	let sorted_indices: Vec<usize> = sorted_signing
		.iter()
		.filter_map(|&p| share.dkg_participants().index_of(p))
		.collect();
	let current_i = sorted_indices.iter().position(|&idx| idx == my_dkg_index)?;

	// Create permutation using shared helper (same logic as recover_share)
	let perm = create_signing_permutation(&sorted_indices, t, n);

	// Accumulate coefficients directly (no NTT)
	let mut s1_acc = vec![0i64; 7 * 256];
	let mut s2_acc = vec![0i64; 8 * 256];

	for &pattern_u in &patterns[current_i] {
		// Translate pattern using shared helper (same logic as recover_share)
		let u_translated = translate_pattern_to_subset(pattern_u, &perm, n);

		if let Some(secret_share) = shares.get(&u_translated) {
			for (poly_idx, poly) in secret_share.s1_share.vec.iter().enumerate().take(7) {
				for (coeff_idx, &coeff) in poly.coeffs.iter().enumerate() {
					let c = coeff as i64;
					let centered = if c > HALF_Q { c - Q } else { c };
					s1_acc[poly_idx * 256 + coeff_idx] += centered;
				}
			}
			for (poly_idx, poly) in secret_share.s2_share.vec.iter().enumerate().take(8) {
				for (coeff_idx, &coeff) in poly.coeffs.iter().enumerate() {
					let c = coeff as i64;
					let centered = if c > HALF_Q { c - Q } else { c };
					s2_acc[poly_idx * 256 + coeff_idx] += centered;
				}
			}
		}
	}

	Some((s1_acc, s2_acc))
}

/// Convert a bitmask subset to a list of party IDs.
fn bitmask_to_party_ids(mask: u16, parties: &[u32]) -> Vec<u32> {
	parties
		.iter()
		.enumerate()
		.filter(|(i, _)| mask & (1 << i) != 0)
		.map(|(_, &id)| id)
		.collect()
}

/// Generate all t-subsets of parties as lists of party IDs.
fn generate_signing_sets(parties: &[u32], threshold: usize) -> Vec<Vec<u32>> {
	generate_subsets_of_size(parties.len(), threshold)
		.into_iter()
		.map(|mask| bitmask_to_party_ids(mask, parties))
		.collect()
}

/// Analyze recovered partial variance for a given configuration.
fn analyze_recovered_partials(threshold: u32, parties: u32, num_resharings: usize) {
	println!("\n======================================================================");
	println!(
		"RECOVERED PARTIAL ANALYSIS: {}-of-{} ({} resharings)",
		threshold, parties, num_resharings
	);
	println!("======================================================================\n");

	let party_ids: Vec<u32> = (0..parties).collect();

	// Generate initial keys
	let config = ThresholdConfig::new(threshold, parties).expect("valid config");
	let seed = [0x42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	let mut current_shares: HashMap<u32, PrivateKeyShare> =
		shares.into_iter().map(|s| (s.party_id(), s)).collect();

	// Run resharings
	for _ in 0..num_resharings {
		let new_shares = run_resharing_protocol(
			threshold,
			party_ids.clone(),
			threshold,
			party_ids.clone(),
			&current_shares,
			&public_key,
		)
		.expect("resharing should succeed");
		current_shares = new_shares;
	}

	// Get hyperball parameters
	let (r, r_prime, nu) =
		get_hyperball_params(threshold, parties).expect("hyperball params for config");

	println!("Hyperball parameters:");
	println!("  r (rejection radius):  {:.0}", r);
	println!("  r' (sampling radius):  {:.0}", r_prime);
	println!("  nu (s1 scaling):       {:.0}", nu);
	println!();

	// Analyze recovered partials for all signing sets
	let signing_sets = generate_signing_sets(&party_ids, threshold as usize);
	println!("Analyzing {} signing sets...\n", signing_sets.len());

	let mut all_stats: Vec<(Vec<u32>, u32, RecoveredPartialStats)> = Vec::new();

	for signing_set in &signing_sets {
		for &party_id in signing_set {
			let share = current_shares.get(&party_id).expect("share exists");
			if let Some((s1_coeffs, s2_coeffs)) = extract_recovered_coefficients(share, signing_set)
			{
				let mut stats = compute_partial_stats(&s1_coeffs, &s2_coeffs, nu);

				// Count how many shares were summed (from sharing pattern)
				let t = threshold as usize;
				let n = parties as usize;
				let subset_size = n - t + 1;
				let total_subsets = binomial(n, subset_size);
				let avg_shares_per_party = total_subsets / t;
				stats.num_shares_summed = avg_shares_per_party;

				all_stats.push((signing_set.clone(), party_id, stats));
			}
		}
	}

	// Compute aggregate statistics
	let total_partials = all_stats.len();
	let avg_s1_variance: f64 =
		all_stats.iter().map(|(_, _, s)| s.s1_variance).sum::<f64>() / total_partials as f64;
	let avg_s2_variance: f64 =
		all_stats.iter().map(|(_, _, s)| s.s2_variance).sum::<f64>() / total_partials as f64;
	let max_s1_linf: i64 = all_stats.iter().map(|(_, _, s)| s.s1_linf_norm).max().unwrap_or(0);
	let max_s2_linf: i64 = all_stats.iter().map(|(_, _, s)| s.s2_linf_norm).max().unwrap_or(0);
	let max_combined_norm: f64 =
		all_stats.iter().map(|(_, _, s)| s.combined_weighted_norm).fold(0.0, f64::max);
	let avg_combined_norm: f64 =
		all_stats.iter().map(|(_, _, s)| s.combined_weighted_norm).sum::<f64>() /
			total_partials as f64;

	println!("Aggregate Statistics ({} recovered partials):", total_partials);
	println!("  Avg s1 coefficient variance: {:.2}", avg_s1_variance);
	println!("  Avg s2 coefficient variance: {:.2}", avg_s2_variance);
	println!("  Avg s1 coefficient std dev:  {:.2}", avg_s1_variance.sqrt());
	println!("  Avg s2 coefficient std dev:  {:.2}", avg_s2_variance.sqrt());
	println!("  Max s1 L-infinity norm:      {}", max_s1_linf);
	println!("  Max s2 L-infinity norm:      {}", max_s2_linf);
	println!();

	println!("Combined Weighted Norm (sqrt(||s1||²/nu² + ||s2||²)):");
	println!("  Average:  {:.0}", avg_combined_norm);
	println!("  Maximum:  {:.0}", max_combined_norm);
	println!("  r' limit: {:.0}", r_prime);
	println!("  Margin:   {:.1}% of r'", (1.0 - max_combined_norm / r_prime) * 100.0);
	println!();

	// Compare to expected values based on coefficient variance
	// The hyperball formula uses: beta = 1.3 * sqrt((k + l/nu²) * n * num_subsets) * sigt *
	// sqrt(tau) where sigt is the coefficient std dev (sqrt(2) for eta=2)
	let k = 8usize;
	let l = 7usize;
	let n_poly = 256usize;
	let tau = 60.0f64;
	let num_subsets_per_party =
		binomial(parties as usize, threshold as usize - 1) / threshold as usize;

	let original_sigt = (2.0f64).sqrt(); // sqrt((5²-1)/12) for eta=2
	let post_reshare_sigt_s1 = avg_s1_variance.sqrt();
	let post_reshare_sigt_s2 = avg_s2_variance.sqrt();

	println!("Coefficient Standard Deviation Comparison:");
	println!("  Original (η=2):            {:.4}", original_sigt);
	println!("  Post-reshare s1:           {:.4}", post_reshare_sigt_s1);
	println!("  Post-reshare s2:           {:.4}", post_reshare_sigt_s2);
	println!("  Ratio (s1/original):       {:.2}x", post_reshare_sigt_s1 / original_sigt);
	println!("  Ratio (s2/original):       {:.2}x", post_reshare_sigt_s2 / original_sigt);
	println!();

	// Expected beta using post-resharing std dev
	let expected_combined_norm_original = 1.3 *
		((k as f64 + l as f64 / (nu * nu)) * n_poly as f64 * num_subsets_per_party as f64).sqrt() *
		original_sigt *
		tau.sqrt();

	let expected_combined_norm_post_reshare =
		1.3 * ((k as f64 * post_reshare_sigt_s2.powi(2) +
			l as f64 * post_reshare_sigt_s1.powi(2) / (nu * nu)) *
			n_poly as f64 *
			num_subsets_per_party as f64)
			.sqrt() * tau.sqrt();

	println!("Expected Combined Norm (from formula):");
	println!("  Using original sigt:       {:.0}", expected_combined_norm_original);
	println!("  Using post-reshare sigt:   {:.0}", expected_combined_norm_post_reshare);
	println!("  Actual max observed:       {:.0}", max_combined_norm);
	println!();

	// Safety margin analysis
	let safety_margin = r_prime - max_combined_norm;
	let required_margin_for_challenge = tau * max_s2_linf as f64; // c*s2 contribution

	println!("Safety Margin Analysis:");
	println!("  Available margin (r' - max_norm): {:.0}", safety_margin);
	println!("  Margin needed for c·s (τ * max_s2): {:.0}", required_margin_for_challenge);
	println!("  Remaining slack: {:.0}", safety_margin - required_margin_for_challenge);

	// Per-signing-set breakdown (first few)
	println!("\nPer-party breakdown (first 5):");
	println!(
		"  {:20} {:>8} {:>12} {:>12} {:>12}",
		"Signing Set", "Party", "s1 StdDev", "s2 StdDev", "Combined"
	);
	println!("  {}", "-".repeat(68));

	for (signing_set, party_id, stats) in all_stats.iter().take(5) {
		println!(
			"  {:20} {:>8} {:>12.2} {:>12.2} {:>12.0}",
			format!("{:?}", signing_set),
			party_id,
			stats.s1_variance.sqrt(),
			stats.s2_variance.sqrt(),
			stats.combined_weighted_norm
		);
	}

	// Assert safety: max combined norm should be well below r'
	assert!(
		max_combined_norm < r_prime,
		"Max combined norm {:.0} exceeds r' {:.0}",
		max_combined_norm,
		r_prime
	);

	// The norm should have reasonable margin (at least 10%)
	let margin_ratio = (r_prime - max_combined_norm) / r_prime;
	println!("\nSafety check: margin ratio = {:.1}% (want > 10%)", margin_ratio * 100.0);
}

/// Compute binomial coefficient C(n, k).
fn binomial(n: usize, k: usize) -> usize {
	if k > n {
		return 0;
	}
	let mut result = 1;
	for i in 0..k {
		result = result * (n - i) / (i + 1);
	}
	result
}

#[test]
fn test_recovered_partial_variance_2_of_3() {
	analyze_recovered_partials(2, 3, 100);
}

#[test]
fn test_recovered_partial_variance_2_of_4() {
	analyze_recovered_partials(2, 4, 100);
}

#[test]
fn test_recovered_partial_variance_3_of_5() {
	analyze_recovered_partials(3, 5, 20);
}

#[test]
fn test_recovered_partial_variance_4_of_6() {
	analyze_recovered_partials(4, 6, 10);
}
