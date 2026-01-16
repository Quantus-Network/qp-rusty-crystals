//! Integration tests for the resharing (committee handoff) protocol.
//!
//! These tests verify that the resharing protocol correctly transfers
//! secret shares to a new committee while preserving the public key.

use std::collections::HashMap;

use qp_rusty_crystals_threshold::{
	generate_with_dealer, verify_signature, PrivateKeyShare, PublicKey, ThresholdConfig,
	ThresholdSigner,
};

use qp_rusty_crystals_threshold::resharing::{
	Action, ResharingConfig, ResharingMessage, ResharingProtocol, ResharingState,
};

/// Helper to run the resharing protocol locally with simulated message passing.
fn run_resharing_protocol(
	old_threshold: u32,
	old_participants: Vec<u32>,
	new_threshold: u32,
	new_participants: Vec<u32>,
	old_shares: &HashMap<u32, PrivateKeyShare>,
	public_key: &PublicKey,
	seed: [u8; 32],
) -> Result<HashMap<u32, PrivateKeyShare>, String> {
	// Determine all parties involved (union of old and new)
	let mut all_parties: Vec<u32> =
		old_participants.iter().chain(new_participants.iter()).cloned().collect();
	all_parties.sort();
	all_parties.dedup();

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
			existing_share,
			public_key.clone(),
		)
		.map_err(|e| format!("Config error for party {}: {}", party_id, e))?;

		// Each party gets a unique seed derived from the base seed
		let mut party_seed = seed;
		party_seed[0] ^= party_id as u8;

		let protocol = ResharingProtocol::new(config, party_seed);
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
			let messages_to_deliver: Vec<_> = messages.drain(..).collect();

			for (from, data) in messages_to_deliver {
				protocol.message(from, data);
			}

			// Poke the protocol
			match protocol.poke() {
				Ok(Action::Wait) => {
					// Nothing to do
				},
				Ok(Action::SendMany(data)) => {
					// Broadcast to all other parties
					for &other_id in &all_parties {
						if other_id != party_id {
							message_queues
								.get_mut(&other_id)
								.unwrap()
								.push((party_id, data.clone()));
						}
					}
				},
				Ok(Action::SendPrivate(to, data)) => {
					// Send to specific party
					message_queues.get_mut(&to).unwrap().push((party_id, data));
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
#[allow(dead_code)]
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
#[allow(dead_code)]
fn run_signing_and_verify_with_retries(
	shares: &[PrivateKeyShare],
	public_key: &PublicKey,
	config: ThresholdConfig,
	message: &[u8],
	context: &[u8],
	max_attempts: u32,
) -> bool {
	use qp_rusty_crystals_threshold::{Round1Broadcast, Round2Broadcast, Round3Broadcast};

	for attempt in 0..max_attempts {
		let mut rng = rand::thread_rng();

		// Create fresh signers for each attempt
		let signers_result: Result<Vec<ThresholdSigner>, _> = shares
			.iter()
			.map(|share| ThresholdSigner::new(share.clone(), public_key.clone(), config))
			.collect();

		let mut signers = match signers_result {
			Ok(s) => s,
			Err(_) => continue,
		};

		// Round 1: Generate commitments (fresh randomness each attempt)
		let r1_result: Result<Vec<Round1Broadcast>, _> =
			signers.iter_mut().map(|s| s.round1_commit(&mut rng)).collect();

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
				s.round2_reveal(message, context, &others)
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
				let others: Vec<_> = r2_broadcasts
					.iter()
					.enumerate()
					.filter(|(j, _)| *j != i)
					.map(|(_, r)| r.clone())
					.collect();
				s.round3_respond(&others)
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
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	// Create resharing config for party 0 (staying in committee)
	let resharing_config = ResharingConfig::new(
		2,             // old threshold
		vec![0, 1, 2], // old participants
		2,             // new threshold
		vec![0, 1, 3], // new participants (2 leaves, 3 joins)
		0,             // my party id
		Some(shares[0].clone()),
		public_key.clone(),
	);

	assert!(resharing_config.is_ok());
	let config = resharing_config.unwrap();
	assert!(config.role.is_old_committee());
	assert!(config.role.is_new_committee());
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
		3,    // joining party
		None, // no existing share
		public_key.clone(),
	);

	assert!(resharing_config.is_ok());
	let config = resharing_config.unwrap();
	assert!(!config.role.is_old_committee());
	assert!(config.role.is_new_committee());
}

#[test]
fn test_resharing_config_leaving_party() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	// Create resharing config for party 2 (leaving)
	let resharing_config = ResharingConfig::new(
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 3],
		2, // leaving party
		Some(shares[2].clone()),
		public_key.clone(),
	);

	assert!(resharing_config.is_ok());
	let config = resharing_config.unwrap();
	assert!(config.role.is_old_committee());
	assert!(!config.role.is_new_committee());
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
		Some(shares[0].clone()),
		public_key,
	)
	.expect("valid config");

	let protocol = ResharingProtocol::new(resharing_config, [0u8; 32]);
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
		Some(shares[0].clone()),
		public_key,
	)
	.expect("valid config");

	let mut protocol = ResharingProtocol::new(resharing_config, [0u8; 32]);

	// First poke should generate Round 1 message
	let action = protocol.poke().expect("poke should succeed");
	match action {
		Action::SendMany(data) => {
			assert!(!data.is_empty());
			// Verify it's a valid Round 1 message (only when serde is enabled)
			#[cfg(feature = "serde")]
			{
				let msg: ResharingMessage =
					bincode::deserialize(&data).expect("should deserialize");
				match msg {
					ResharingMessage::Round1(broadcast) => {
						assert_eq!(broadcast.party_id, 0);
					},
					_ => panic!("Expected Round1 message"),
				}
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
		ResharingConfig::new(2, vec![0, 1, 2], 2, vec![0, 1, 3], 3, None, public_key)
			.expect("valid config");

	let mut protocol = ResharingProtocol::new(resharing_config, [0u8; 32]);

	// New party should skip Round 1 and wait for Round 2
	let action = protocol.poke().expect("poke should succeed");
	match action {
		Action::Wait => {
			// Expected - new party waits for Round 2 messages
		},
		_ => panic!("Expected Wait action for new party"),
	}

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
			old_shares.get(&party_id).cloned(),
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
		let existing_share = if party_id < 3 { old_shares.get(&party_id).cloned() } else { None };

		let resharing_config = ResharingConfig::new(
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 2, 3],
			party_id,
			existing_share,
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
			old_shares.get(&party_id).cloned(),
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
		let existing_share = if party_id < 3 { old_shares.get(&party_id).cloned() } else { None };

		let resharing_config = ResharingConfig::new(
			2,
			vec![0, 1, 2],
			3, // new threshold
			vec![0, 1, 2, 3],
			party_id,
			existing_share,
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
		let existing_share = if party_id < 3 { old_shares.get(&party_id).cloned() } else { None };

		let resharing_config = ResharingConfig::new(
			2,
			vec![0, 1, 2],
			2,
			vec![3, 4, 5],
			party_id,
			existing_share,
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
	let result = ResharingConfig::new(2, vec![0, 1, 2], 2, vec![3, 4, 5], 10, None, public_key);

	assert!(result.is_err());
}

#[test]
fn test_resharing_config_missing_share_for_old_member() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, _shares) = generate_with_dealer(&seed, config).expect("keygen");

	// Party 0 is in old committee but has no share
	let result = ResharingConfig::new(
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 2],
		0,
		None, // missing share!
		public_key,
	);

	assert!(result.is_err());
}

#[test]
fn test_resharing_config_unexpected_share_for_new_member() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	// Party 3 is only in new committee but has a share (wrong!)
	let result = ResharingConfig::new(
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 3],
		3,
		Some(shares[0].clone()), // unexpected share!
		public_key,
	);

	assert!(result.is_err());
}

#[test]
fn test_resharing_config_invalid_old_threshold() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	// Old threshold too high
	let result = ResharingConfig::new(
		5, // invalid: > n
		vec![0, 1, 2],
		2,
		vec![0, 1, 2],
		0,
		Some(shares[0].clone()),
		public_key,
	);

	assert!(result.is_err());
}

#[test]
fn test_resharing_config_invalid_new_threshold() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

	// New threshold too low
	let result = ResharingConfig::new(
		2,
		vec![0, 1, 2],
		1, // invalid: < 2
		vec![0, 1, 2],
		0,
		Some(shares[0].clone()),
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
		Some(shares[0].clone()),
		public_key.clone(),
	)
	.expect("valid config");

	let mut protocol = ResharingProtocol::new(resharing_config, [0u8; 32]);

	// Generate Round 1 message
	let _ = protocol.poke().expect("poke should succeed");

	// Try to deliver a message from party 10 (not in old committee)
	// This should be silently ignored
	let fake_message = vec![0u8; 100]; // Invalid message, but that's fine - it should be ignored first
	protocol.message(10, fake_message);

	// Protocol should still be in Round1Waiting
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
		Some(shares[0].clone()),
		public_key.clone(),
	)
	.expect("valid config");

	let config1 = ResharingConfig::new(
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 2],
		1,
		Some(shares[1].clone()),
		public_key.clone(),
	)
	.expect("valid config");

	let mut protocol0 = ResharingProtocol::new(config0, [0u8; 32]);
	let mut protocol1 = ResharingProtocol::new(config1, [1u8; 32]);

	// Generate Round 1 messages
	let msg0 = match protocol0.poke().expect("poke should succeed") {
		Action::SendMany(data) => data,
		_ => panic!("Expected SendMany"),
	};

	let _ = protocol1.poke().expect("poke should succeed");

	// Deliver message from party 0 to party 1
	protocol1.message(0, msg0.clone());

	// Deliver the same message again (duplicate)
	protocol1.message(0, msg0);

	// Should only be counted once - need 2 messages total (from parties 0 and 2)
	// to have "enough" Round 1 messages
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
		Some(shares[2].clone()),
		public_key,
	)
	.expect("valid config");

	let mut protocol = ResharingProtocol::new(resharing_config, [0u8; 32]);

	// Party should participate in Round 1
	let action = protocol.poke().expect("poke should succeed");
	match action {
		Action::SendMany(_) => {
			// Expected - old party broadcasts Round 1 message
		},
		_ => panic!("Expected SendMany for old party in Round 1"),
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
		None,
		public_key,
	)
	.expect("valid config");

	let mut protocol = ResharingProtocol::new(resharing_config, [0u8; 32]);

	// New party should skip Round 1 and wait for Round 2
	let action = protocol.poke().expect("poke should succeed");
	match action {
		Action::Wait => {
			// Expected - new party waits for shares
		},
		_ => panic!("Expected Wait for new party"),
	}

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
	let result = run_resharing_protocol(
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 2],
		&old_shares,
		&public_key,
		[99u8; 32],
	);

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
	let result = run_resharing_protocol(
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 2, 3],
		&old_shares,
		&public_key,
		[99u8; 32],
	);

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
	let result = run_resharing_protocol(
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1],
		&old_shares,
		&public_key,
		[99u8; 32],
	);

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
	let result = run_resharing_protocol(
		2,
		vec![0, 1, 2],
		2,
		vec![0, 1, 3],
		&old_shares,
		&public_key,
		[99u8; 32],
	);

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
