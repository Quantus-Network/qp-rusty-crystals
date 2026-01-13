//! Protocol trait implementation for DKG.
//!
//! This module implements the `Protocol` trait pattern used by NEAR MPC,
//! allowing the DKG to be driven by the standard `run_protocol` function.
//!
//! The protocol uses a poke/message pattern:
//! - `poke()` is called repeatedly to advance the protocol
//! - `message()` is called when a message arrives from another party
//! - `poke()` returns an `Action` indicating what to do next

use std::collections::HashMap;

use rand::{Rng, SeedableRng};

use crate::error::ThresholdError;

use super::state::{DkgState, DkgStateData};
use super::types::{
    DkgConfig, DkgMessage, DkgOutput, DkgRound1Broadcast, DkgRound2Broadcast, DkgRound3Broadcast,
    DkgRound4Broadcast, ParticipantId, PartyContributions, SubsetContribution, SubsetMask,
    COMMITMENT_HASH_SIZE, K, L, N, RHO_CONTRIBUTION_SIZE, SESSION_ID_SIZE,
};

// ============================================================================
// Action Enum (mirrors NEAR's threshold-signatures Protocol trait)
// ============================================================================

/// Represents an action to be taken by the protocol driver.
///
/// This mirrors the `Action` enum from NEAR's `threshold-signatures` crate.
#[derive(Debug, Clone)]
pub enum Action<T> {
    /// Do nothing, waiting for more messages.
    Wait,
    /// Send a message to all other participants.
    SendMany(Vec<u8>),
    /// Send a private message to a specific participant.
    SendPrivate(ParticipantId, Vec<u8>),
    /// The protocol has completed, returning the output.
    Return(T),
}

// ============================================================================
// Protocol Error
// ============================================================================

/// Errors that can occur during the DKG protocol.
#[derive(Debug, Clone)]
pub enum DkgProtocolError {
    /// The protocol is in an invalid state for the requested operation.
    InvalidState(String),
    /// A message was received from an unknown party.
    UnknownParty(ParticipantId),
    /// A duplicate message was received from a party.
    DuplicateMessage(ParticipantId),
    /// Commitment verification failed for a party.
    CommitmentMismatch(ParticipantId),
    /// Contribution bounds verification failed for a party.
    InvalidContributionBounds(ParticipantId),
    /// Consensus was not reached on the public key.
    ConsensusFailure(Vec<ParticipantId>),
    /// A party reported failure.
    PartyFailure(Vec<ParticipantId>),
    /// Serialization error.
    SerializationError(String),
    /// Randomness generation error.
    RandomnessError,
    /// Internal error.
    InternalError(String),
}

impl std::fmt::Display for DkgProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DkgProtocolError::InvalidState(s) => write!(f, "Invalid state: {}", s),
            DkgProtocolError::UnknownParty(p) => write!(f, "Unknown party: {}", p),
            DkgProtocolError::DuplicateMessage(p) => write!(f, "Duplicate message from party: {}", p),
            DkgProtocolError::CommitmentMismatch(p) => {
                write!(f, "Commitment mismatch for party: {}", p)
            }
            DkgProtocolError::InvalidContributionBounds(p) => {
                write!(f, "Invalid contribution bounds for party: {}", p)
            }
            DkgProtocolError::ConsensusFailure(parties) => {
                write!(f, "Consensus failure, mismatched parties: {:?}", parties)
            }
            DkgProtocolError::PartyFailure(parties) => {
                write!(f, "Party failure: {:?}", parties)
            }
            DkgProtocolError::SerializationError(s) => write!(f, "Serialization error: {}", s),
            DkgProtocolError::RandomnessError => write!(f, "Randomness generation error"),
            DkgProtocolError::InternalError(s) => write!(f, "Internal error: {}", s),
        }
    }
}

impl std::error::Error for DkgProtocolError {}

impl From<DkgProtocolError> for ThresholdError {
    fn from(e: DkgProtocolError) -> Self {
        ThresholdError::InvalidConfiguration(e.to_string())
    }
}

// ============================================================================
// DKG Protocol Implementation
// ============================================================================

/// The main DKG protocol state machine.
///
/// This struct implements the distributed key generation protocol for
/// threshold Dilithium signatures. It follows the poke/message pattern
/// used by NEAR MPC.
///
/// # Usage
///
/// ```ignore
/// let mut dkg = DilithiumDkg::new(config, rng)?;
///
/// loop {
///     match dkg.poke()? {
///         Action::Wait => {
///             // Wait for messages from other parties
///         }
///         Action::SendMany(data) => {
///             // Broadcast data to all other parties
///             for party in other_parties {
///                 send(party, data.clone());
///             }
///         }
///         Action::SendPrivate(party, data) => {
///             // Send data privately to the specified party
///             send(party, data);
///         }
///         Action::Return(output) => {
///             // Protocol complete!
///             break;
///         }
///     }
///
///     // When a message arrives:
///     dkg.message(from_party, data);
/// }
/// ```
pub struct DilithiumDkg {
    /// Internal state data.
    state_data: DkgStateData,
    /// Random number generator.
    rng: rand::rngs::StdRng,
    /// Whether we've sent our message for the current round.
    sent_current_round: bool,
}

impl DilithiumDkg {
    /// Create a new DKG protocol instance from a seed.
    ///
    /// # Arguments
    /// * `config` - The DKG configuration
    /// * `seed` - A 32-byte seed for deterministic randomness
    pub fn new(config: DkgConfig, seed: [u8; 32]) -> Self {
        Self {
            state_data: DkgStateData::new(config),
            rng: rand::rngs::StdRng::from_seed(seed),
            sent_current_round: false,
        }
    }

    /// Get the current protocol state.
    pub fn state(&self) -> &DkgState {
        &self.state_data.state
    }

    /// Get this party's ID.
    pub fn my_party_id(&self) -> ParticipantId {
        self.state_data.config.my_party_id
    }

    /// Get the DKG configuration.
    pub fn config(&self) -> &DkgConfig {
        &self.state_data.config
    }

    /// Poke the protocol to advance it.
    ///
    /// This should be called repeatedly until it returns `Action::Return`
    /// or an error. Between calls, messages from other parties should be
    /// delivered via the `message()` method.
    pub fn poke(&mut self) -> Result<Action<DkgOutput>, DkgProtocolError> {
        match &self.state_data.state {
            DkgState::Initialized => {
                // Start Round 1
                self.state_data.transition_to(DkgState::Round1Generating);
                self.sent_current_round = false;
                self.poke()
            }

            DkgState::Round1Generating => {
                if self.sent_current_round {
                    self.state_data.transition_to(DkgState::Round1Waiting);
                    return Ok(Action::Wait);
                }

                // Generate session ID contribution
                let session_id: [u8; SESSION_ID_SIZE] = self.rng.gen();

                self.state_data.round1.my_contribution = session_id;
                self.state_data
                    .round1
                    .add_contribution(self.my_party_id(), session_id);

                let msg = DkgRound1Broadcast {
                    party_id: self.my_party_id(),
                    session_id_contribution: session_id,
                };

                self.sent_current_round = true;
                Ok(Action::SendMany(self.serialize_message(&DkgMessage::Round1(msg))?))
            }

            DkgState::Round1Waiting => {
                if self.state_data.can_advance() {
                    // Compute combined session ID
                    self.compute_combined_session_id();
                    self.state_data.transition_to(DkgState::Round2Generating);
                    self.sent_current_round = false;
                    self.poke()
                } else {
                    Ok(Action::Wait)
                }
            }

            DkgState::Round2Generating => {
                if self.sent_current_round {
                    self.state_data.transition_to(DkgState::Round2Waiting);
                    return Ok(Action::Wait);
                }

                // Generate contributions for all subsets
                let contributions = self.generate_contributions()?;
                let commitment_hash = self.compute_commitment_hash(&contributions);

                self.state_data.round2.my_contributions = Some(contributions);
                self.state_data.round2.my_commitment_hash = commitment_hash;
                self.state_data
                    .round2
                    .add_commitment_hash(self.my_party_id(), commitment_hash);

                let msg = DkgRound2Broadcast {
                    party_id: self.my_party_id(),
                    commitment_hash,
                };

                self.sent_current_round = true;
                Ok(Action::SendMany(self.serialize_message(&DkgMessage::Round2(msg))?))
            }

            DkgState::Round2Waiting => {
                if self.state_data.can_advance() {
                    self.state_data.transition_to(DkgState::Round3Revealing);
                    self.sent_current_round = false;
                    self.poke()
                } else {
                    Ok(Action::Wait)
                }
            }

            DkgState::Round3Revealing => {
                if self.sent_current_round {
                    self.state_data.transition_to(DkgState::Round3Waiting);
                    return Ok(Action::Wait);
                }

                // Reveal our contributions
                let contributions = self
                    .state_data
                    .round2
                    .my_contributions
                    .clone()
                    .ok_or_else(|| {
                        DkgProtocolError::InternalError("Missing my contributions".into())
                    })?;

                // Add our own contributions to round3 data
                self.state_data
                    .round3
                    .add_contributions(self.my_party_id(), contributions.clone());

                let msg = DkgRound3Broadcast {
                    party_id: self.my_party_id(),
                    contributions,
                };

                self.sent_current_round = true;
                Ok(Action::SendMany(self.serialize_message(&DkgMessage::Round3(msg))?))
            }

            DkgState::Round3Waiting => {
                if self.state_data.can_advance() {
                    // Verify all contributions
                    self.verify_all_contributions()?;

                    self.state_data.transition_to(DkgState::Round4Confirming);
                    self.sent_current_round = false;
                    self.poke()
                } else {
                    Ok(Action::Wait)
                }
            }

            DkgState::Round4Confirming => {
                if self.sent_current_round {
                    self.state_data.transition_to(DkgState::Round4Waiting);
                    return Ok(Action::Wait);
                }

                // Compute final shares and public key
                let (success, public_key_hash) = match self.compute_final_output() {
                    Ok(output) => {
                        let pk_hash = self.hash_public_key(&output.public_key);
                        self.state_data.round4.my_public_key_hash = pk_hash;
                        self.state_data.output = Some(output);
                        (true, pk_hash)
                    }
                    Err(e) => {
                        // Log error but continue to send confirmation
                        eprintln!("DKG computation failed: {}", e);
                        (false, [0u8; COMMITMENT_HASH_SIZE])
                    }
                };

                let msg = DkgRound4Broadcast {
                    party_id: self.my_party_id(),
                    success,
                    public_key_hash,
                };

                self.state_data
                    .round4
                    .add_confirmation(self.my_party_id(), msg.clone());

                self.sent_current_round = true;
                Ok(Action::SendMany(self.serialize_message(&DkgMessage::Round4(msg))?))
            }

            DkgState::Round4Waiting => {
                if self.state_data.can_advance() {
                    // Check consensus
                    if !self.state_data.round4.consensus_reached() {
                        let failed = self.state_data.round4.failed_parties();
                        if !failed.is_empty() {
                            return Err(DkgProtocolError::PartyFailure(failed));
                        }
                        let mismatched = self.state_data.round4.mismatched_parties();
                        return Err(DkgProtocolError::ConsensusFailure(mismatched));
                    }

                    // Return the output
                    let output = self.state_data.output.clone().ok_or_else(|| {
                        DkgProtocolError::InternalError("Missing output".into())
                    })?;

                    self.state_data.transition_to(DkgState::Complete);
                    Ok(Action::Return(output))
                } else {
                    Ok(Action::Wait)
                }
            }

            DkgState::Complete => {
                let output = self.state_data.output.clone().ok_or_else(|| {
                    DkgProtocolError::InternalError("Missing output in Complete state".into())
                })?;
                Ok(Action::Return(output))
            }

            DkgState::Failed(reason) => {
                Err(DkgProtocolError::InvalidState(format!("Protocol failed: {}", reason)))
            }
        }
    }

    /// Deliver a message from another party.
    ///
    /// This should be called when a message is received from another party.
    /// The message will be processed according to the current protocol state.
    pub fn message(&mut self, from: ParticipantId, data: Vec<u8>) {
        // Deserialize and process the message
        let msg = match self.deserialize_message(&data) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("Failed to deserialize message from {}: {}", from, e);
                return;
            }
        };

        // Verify sender matches message
        if msg.party_id() != from {
            eprintln!(
                "Message party_id {} doesn't match sender {}",
                msg.party_id(),
                from
            );
            return;
        }

        // Process based on message type
        let result = match msg {
            DkgMessage::Round1(m) => self.state_data.process_round1(m),
            DkgMessage::Round2(m) => self.state_data.process_round2(m),
            DkgMessage::Round3(m) => self.state_data.process_round3(m),
            DkgMessage::Round4(m) => self.state_data.process_round4(m),
        };

        if let Err(e) = result {
            eprintln!("Failed to process message from {}: {}", from, e);
        }
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// Serialize a message for transmission.
    fn serialize_message(&self, msg: &DkgMessage) -> Result<Vec<u8>, DkgProtocolError> {
        #[cfg(feature = "serde")]
        {
            bincode::serialize(msg)
                .map_err(|e| DkgProtocolError::SerializationError(e.to_string()))
        }
        #[cfg(not(feature = "serde"))]
        {
            // Fallback: simple custom serialization
            self.serialize_message_custom(msg)
        }
    }

    /// Deserialize a message from received bytes.
    fn deserialize_message(&self, data: &[u8]) -> Result<DkgMessage, DkgProtocolError> {
        #[cfg(feature = "serde")]
        {
            bincode::deserialize(data)
                .map_err(|e| DkgProtocolError::SerializationError(e.to_string()))
        }
        #[cfg(not(feature = "serde"))]
        {
            // Fallback: simple custom deserialization
            self.deserialize_message_custom(data)
        }
    }

    /// Custom serialization when serde is not available.
    #[cfg(not(feature = "serde"))]
    fn serialize_message_custom(&self, msg: &DkgMessage) -> Result<Vec<u8>, DkgProtocolError> {
        let mut buf = Vec::new();

        match msg {
            DkgMessage::Round1(m) => {
                buf.push(1u8); // Round tag
                buf.push(m.party_id);
                buf.extend_from_slice(&m.session_id_contribution);
            }
            DkgMessage::Round2(m) => {
                buf.push(2u8);
                buf.push(m.party_id);
                buf.extend_from_slice(&m.commitment_hash);
            }
            DkgMessage::Round3(m) => {
                buf.push(3u8);
                buf.push(m.party_id);
                buf.push(m.contributions.party_id);
                buf.extend_from_slice(&m.contributions.rho_contribution);
                // Serialize subset contributions count
                let count = m.contributions.subset_contributions.len() as u16;
                buf.extend_from_slice(&count.to_le_bytes());
                // Serialize each subset contribution
                for (mask, contrib) in &m.contributions.subset_contributions {
                    buf.extend_from_slice(&mask.to_le_bytes());
                    // Serialize s1 polynomials
                    for poly in &contrib.s1 {
                        for coeff in poly {
                            buf.extend_from_slice(&coeff.to_le_bytes());
                        }
                    }
                    // Serialize s2 polynomials
                    for poly in &contrib.s2 {
                        for coeff in poly {
                            buf.extend_from_slice(&coeff.to_le_bytes());
                        }
                    }
                }
            }
            DkgMessage::Round4(m) => {
                buf.push(4u8);
                buf.push(m.party_id);
                buf.push(if m.success { 1u8 } else { 0u8 });
                buf.extend_from_slice(&m.public_key_hash);
            }
        }

        Ok(buf)
    }

    /// Custom deserialization when serde is not available.
    #[cfg(not(feature = "serde"))]
    fn deserialize_message_custom(&self, data: &[u8]) -> Result<DkgMessage, DkgProtocolError> {
        if data.is_empty() {
            return Err(DkgProtocolError::SerializationError("Empty data".into()));
        }

        let round = data[0];
        let data = &data[1..];

        match round {
            1 => {
                if data.len() < 1 + SESSION_ID_SIZE {
                    return Err(DkgProtocolError::SerializationError("Round1 too short".into()));
                }
                let party_id = data[0];
                let mut session_id = [0u8; SESSION_ID_SIZE];
                session_id.copy_from_slice(&data[1..1 + SESSION_ID_SIZE]);
                Ok(DkgMessage::Round1(DkgRound1Broadcast {
                    party_id,
                    session_id_contribution: session_id,
                }))
            }
            2 => {
                if data.len() < 1 + COMMITMENT_HASH_SIZE {
                    return Err(DkgProtocolError::SerializationError("Round2 too short".into()));
                }
                let party_id = data[0];
                let mut hash = [0u8; COMMITMENT_HASH_SIZE];
                hash.copy_from_slice(&data[1..1 + COMMITMENT_HASH_SIZE]);
                Ok(DkgMessage::Round2(DkgRound2Broadcast {
                    party_id,
                    commitment_hash: hash,
                }))
            }
            3 => {
                // More complex deserialization for Round3
                self.deserialize_round3_custom(data)
            }
            4 => {
                if data.len() < 2 + COMMITMENT_HASH_SIZE {
                    return Err(DkgProtocolError::SerializationError("Round4 too short".into()));
                }
                let party_id = data[0];
                let success = data[1] != 0;
                let mut hash = [0u8; COMMITMENT_HASH_SIZE];
                hash.copy_from_slice(&data[2..2 + COMMITMENT_HASH_SIZE]);
                Ok(DkgMessage::Round4(DkgRound4Broadcast {
                    party_id,
                    success,
                    public_key_hash: hash,
                }))
            }
            _ => Err(DkgProtocolError::SerializationError(format!(
                "Unknown round: {}",
                round
            ))),
        }
    }

    #[cfg(not(feature = "serde"))]
    fn deserialize_round3_custom(&self, data: &[u8]) -> Result<DkgMessage, DkgProtocolError> {
        let mut offset = 0;

        if data.len() < 2 + RHO_CONTRIBUTION_SIZE + 2 {
            return Err(DkgProtocolError::SerializationError("Round3 too short".into()));
        }

        let party_id = data[offset];
        offset += 1;
        let contrib_party_id = data[offset];
        offset += 1;

        let mut rho = [0u8; RHO_CONTRIBUTION_SIZE];
        rho.copy_from_slice(&data[offset..offset + RHO_CONTRIBUTION_SIZE]);
        offset += RHO_CONTRIBUTION_SIZE;

        let count = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        let mut subset_contributions = HashMap::new();
        let poly_size = N * 4; // i32 = 4 bytes
        let contrib_size = 2 + (L * poly_size) + (K * poly_size); // mask + s1 + s2

        for _ in 0..count {
            if data.len() < offset + contrib_size {
                return Err(DkgProtocolError::SerializationError(
                    "Round3 subset data too short".into(),
                ));
            }

            let mask = u16::from_le_bytes([data[offset], data[offset + 1]]);
            offset += 2;

            let mut s1 = vec![[0i32; N]; L];
            for poly in &mut s1 {
                for coeff in poly.iter_mut() {
                    *coeff = i32::from_le_bytes([
                        data[offset],
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                    ]);
                    offset += 4;
                }
            }

            let mut s2 = vec![[0i32; N]; K];
            for poly in &mut s2 {
                for coeff in poly.iter_mut() {
                    *coeff = i32::from_le_bytes([
                        data[offset],
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                    ]);
                    offset += 4;
                }
            }

            subset_contributions.insert(mask, SubsetContribution { s1, s2 });
        }

        Ok(DkgMessage::Round3(DkgRound3Broadcast {
            party_id,
            contributions: PartyContributions {
                party_id: contrib_party_id,
                rho_contribution: rho,
                subset_contributions,
            },
        }))
    }

    /// Compute the combined session ID from all contributions.
    fn compute_combined_session_id(&mut self) {
        use qp_rusty_crystals_dilithium::fips202;

        let mut state = fips202::KeccakState::default();

        // Sort by party ID for deterministic ordering
        let mut contributions: Vec<_> = self.state_data.round1.session_ids.iter().collect();
        contributions.sort_by_key(|(id, _)| *id);

        for (_, contribution) in contributions {
            fips202::shake256_absorb(&mut state, contribution, SESSION_ID_SIZE);
        }
        fips202::shake256_finalize(&mut state);

        let mut combined = [0u8; SESSION_ID_SIZE];
        fips202::shake256_squeeze(&mut combined, SESSION_ID_SIZE, &mut state);

        self.state_data.round1.combined_session_id = Some(combined);
    }

    /// Generate contributions for all subsets this party belongs to.
    fn generate_contributions(&mut self) -> Result<PartyContributions, DkgProtocolError> {
        let my_id = self.my_party_id();
        let threshold = self.state_data.config.threshold();
        let parties = self.state_data.config.total_parties();

        let mut contributions = PartyContributions::new(my_id);

        // Generate rho contribution
        contributions.rho_contribution = self.rng.gen();

        // Generate contributions for each subset this party belongs to
        let subsets = self.compute_subsets_for_party(my_id, threshold, parties);

        for subset_mask in subsets {
            let contrib = self.generate_subset_contribution(subset_mask)?;
            contributions.subset_contributions.insert(subset_mask, contrib);
        }

        Ok(contributions)
    }

    /// Compute all subset masks that contain a given party.
    fn compute_subsets_for_party(
        &self,
        party_id: ParticipantId,
        threshold: u8,
        parties: u8,
    ) -> Vec<SubsetMask> {
        let subset_size = (parties - threshold + 1) as usize;
        let mut subsets = Vec::new();

        // Generate all subsets of size (n - t + 1) containing this party
        let mut subset: SubsetMask = (1 << subset_size) - 1;
        let max_val: SubsetMask = 1 << parties;

        while subset < max_val {
            // Check if this party is in the subset
            if (subset & (1 << party_id)) != 0 {
                subsets.push(subset);
            }

            // Gosper's hack for next subset of same size
            let c = subset & (!subset + 1);
            let r = subset + c;
            subset = (((r ^ subset) >> 2) / c) | r;
        }

        subsets
    }

    /// Generate a random η-bounded contribution for a subset.
    fn generate_subset_contribution(
        &mut self,
        _subset_mask: SubsetMask,
    ) -> Result<SubsetContribution, DkgProtocolError> {
        let eta = 2i32; // ML-DSA-87 η parameter
        let mut contrib = SubsetContribution::new();

        // Generate random η-bounded polynomials for s1
        for poly in &mut contrib.s1 {
            for coeff in poly.iter_mut() {
                *coeff = self.sample_bounded_coefficient(eta)?;
            }
        }

        // Generate random η-bounded polynomials for s2
        for poly in &mut contrib.s2 {
            for coeff in poly.iter_mut() {
                *coeff = self.sample_bounded_coefficient(eta)?;
            }
        }

        Ok(contrib)
    }

    /// Sample a random coefficient in [-eta, eta].
    fn sample_bounded_coefficient(&mut self, eta: i32) -> Result<i32, DkgProtocolError> {
        let bound = (2 * eta + 1) as u32;
        loop {
            let b: u8 = self.rng.gen();
            let b = b as u32;
            if b < (256 / bound) * bound {
                return Ok((b % bound) as i32 - eta);
            }
        }
    }

    /// Compute the commitment hash for contributions.
    fn compute_commitment_hash(&self, contributions: &PartyContributions) -> [u8; COMMITMENT_HASH_SIZE] {
        use qp_rusty_crystals_dilithium::fips202;

        let mut state = fips202::KeccakState::default();

        // Include party ID
        fips202::shake256_absorb(&mut state, &[contributions.party_id], 1);

        // Include rho contribution
        fips202::shake256_absorb(
            &mut state,
            &contributions.rho_contribution,
            RHO_CONTRIBUTION_SIZE,
        );

        // Include subset contributions in sorted order
        let mut subsets: Vec<_> = contributions.subset_contributions.iter().collect();
        subsets.sort_by_key(|(mask, _)| *mask);

        for (mask, contrib) in subsets {
            fips202::shake256_absorb(&mut state, &mask.to_le_bytes(), 2);

            for poly in &contrib.s1 {
                for coeff in poly {
                    fips202::shake256_absorb(&mut state, &coeff.to_le_bytes(), 4);
                }
            }
            for poly in &contrib.s2 {
                for coeff in poly {
                    fips202::shake256_absorb(&mut state, &coeff.to_le_bytes(), 4);
                }
            }
        }

        // Include session ID for domain separation
        if let Some(session_id) = &self.state_data.round1.combined_session_id {
            fips202::shake256_absorb(&mut state, session_id, SESSION_ID_SIZE);
        }

        fips202::shake256_finalize(&mut state);

        let mut hash = [0u8; COMMITMENT_HASH_SIZE];
        fips202::shake256_squeeze(&mut hash, COMMITMENT_HASH_SIZE, &mut state);

        hash
    }

    /// Verify all revealed contributions against their commitments.
    fn verify_all_contributions(&mut self) -> Result<(), DkgProtocolError> {
        let eta = 2i32; // ML-DSA-87 η parameter
        let my_id = self.my_party_id();

        // Collect party IDs and contributions to avoid borrow issues
        let parties_to_verify: Vec<(ParticipantId, PartyContributions)> = self
            .state_data
            .round3
            .contributions
            .iter()
            .map(|(&id, c)| (id, c.clone()))
            .collect();

        for (party_id, contributions) in parties_to_verify {
            // Skip self (already verified implicitly)
            if party_id == my_id {
                self.state_data.round3.set_verification_result(party_id, true);
                continue;
            }

            // Verify commitment hash matches
            let expected_hash = self
                .state_data
                .round2
                .commitment_hashes
                .get(&party_id)
                .ok_or_else(|| {
                    DkgProtocolError::InternalError(format!(
                        "Missing commitment hash for party {}",
                        party_id
                    ))
                })?
                .clone();

            let actual_hash = self.compute_commitment_hash(&contributions);

            if actual_hash != expected_hash {
                self.state_data.round3.set_verification_result(party_id, false);
                return Err(DkgProtocolError::CommitmentMismatch(party_id));
            }

            // Verify coefficient bounds
            for (_, subset_contrib) in &contributions.subset_contributions {
                if !subset_contrib.verify_bounds(eta) {
                    self.state_data.round3.set_verification_result(party_id, false);
                    return Err(DkgProtocolError::InvalidContributionBounds(party_id));
                }
            }

            self.state_data.round3.set_verification_result(party_id, true);
        }

        Ok(())
    }

    /// Compute the final DKG output (public key and private share).
    fn compute_final_output(&mut self) -> Result<DkgOutput, DkgProtocolError> {
        use crate::keys::{PrivateKeyShare, PublicKey, SecretShareData, PUBLIC_KEY_SIZE, TR_SIZE};
        use crate::protocol::primitives::Q;
        use qp_rusty_crystals_dilithium::{fips202, packing, poly, polyvec};

        let my_id = self.my_party_id();
        let threshold = self.state_data.config.threshold();
        let parties = self.state_data.config.total_parties();

        // Combine rho contributions
        let mut rho = [0u8; 32];
        {
            let mut state = fips202::KeccakState::default();
            let mut contribs: Vec<_> = self.state_data.round3.contributions.iter().collect();
            contribs.sort_by_key(|(id, _)| *id);

            for (_, contrib) in contribs {
                fips202::shake256_absorb(&mut state, &contrib.rho_contribution, 32);
            }
            fips202::shake256_finalize(&mut state);
            fips202::shake256_squeeze(&mut rho, 32, &mut state);
        }

        // Compute combined shares for each subset
        let mut combined_shares: HashMap<SubsetMask, SecretShareData> = HashMap::new();
        let my_subsets = self.compute_subsets_for_party(my_id, threshold, parties);

        for subset_mask in &my_subsets {
            let mut s1_combined = vec![[0i32; N]; L];
            let mut s2_combined = vec![[0i32; N]; K];

            // Sum contributions from all parties in this subset
            for party_id in 0..parties {
                if (subset_mask & (1 << party_id)) == 0 {
                    continue;
                }

                if let Some(party_contrib) = self.state_data.round3.contributions.get(&party_id) {
                    if let Some(subset_contrib) =
                        party_contrib.subset_contributions.get(subset_mask)
                    {
                        for i in 0..L {
                            for j in 0..N {
                                s1_combined[i][j] =
                                    s1_combined[i][j].wrapping_add(subset_contrib.s1[i][j]);
                            }
                        }
                        for i in 0..K {
                            for j in 0..N {
                                s2_combined[i][j] =
                                    s2_combined[i][j].wrapping_add(subset_contrib.s2[i][j]);
                            }
                        }
                    }
                }
            }

            // Normalize coefficients mod q
            for i in 0..L {
                for j in 0..N {
                    let c = s1_combined[i][j];
                    s1_combined[i][j] = ((c % Q) + Q) % Q;
                }
            }
            for i in 0..K {
                for j in 0..N {
                    let c = s2_combined[i][j];
                    s2_combined[i][j] = ((c % Q) + Q) % Q;
                }
            }

            combined_shares.insert(
                *subset_mask,
                SecretShareData {
                    s1: s1_combined,
                    s2: s2_combined,
                },
            );
        }

        // Compute total s1, s2 for public key generation
        let mut s1_total = polyvec::Polyvecl::default();
        let mut s2_total = polyvec::Polyveck::default();

        // Sum all subset contributions (they partition the total)
        for (_, contrib) in &self.state_data.round3.contributions {
            for (_, subset_contrib) in &contrib.subset_contributions {
                for i in 0..L {
                    for j in 0..N {
                        s1_total.vec[i].coeffs[j] =
                            s1_total.vec[i].coeffs[j].wrapping_add(subset_contrib.s1[i][j]);
                    }
                }
                for i in 0..K {
                    for j in 0..N {
                        s2_total.vec[i].coeffs[j] =
                            s2_total.vec[i].coeffs[j].wrapping_add(subset_contrib.s2[i][j]);
                    }
                }
            }
        }

        // Normalize totals
        for i in 0..L {
            for j in 0..N {
                let c = s1_total.vec[i].coeffs[j];
                s1_total.vec[i].coeffs[j] = ((c % Q) + Q) % Q;
            }
        }
        for i in 0..K {
            for j in 0..N {
                let c = s2_total.vec[i].coeffs[j];
                s2_total.vec[i].coeffs[j] = ((c % Q) + Q) % Q;
            }
        }

        // Convert s1 to NTT domain
        let mut s1h_total = s1_total.clone();
        for i in 0..L {
            crate::circl_ntt::ntt(&mut s1h_total.vec[i]);
        }

        // Expand matrix A from rho
        let mut a_matrix: Vec<polyvec::Polyvecl> =
            (0..K).map(|_| polyvec::Polyvecl::default()).collect();
        polyvec::matrix_expand(&mut a_matrix, &rho);

        // Compute t = A*s1 + s2
        let mut t = polyvec::Polyveck::default();
        for i in 0..K {
            for j in 0..L {
                let mut temp = poly::Poly::default();
                poly::pointwise_montgomery(&mut temp, &a_matrix[i].vec[j], &s1h_total.vec[j]);
                t.vec[i] = poly::add(&t.vec[i], &temp);
            }
            poly::reduce(&mut t.vec[i]);
            poly::invntt_tomont(&mut t.vec[i]);
        }

        // Add s2
        for i in 0..K {
            t.vec[i] = poly::add(&t.vec[i], &s2_total.vec[i]);
        }

        // Normalize t
        for i in 0..K {
            poly::reduce(&mut t.vec[i]);
            for j in 0..N {
                let coeff = t.vec[i].coeffs[j];
                t.vec[i].coeffs[j] = ((coeff % Q) + Q) % Q;
            }
        }

        // Extract t1 (high bits)
        let mut t0 = polyvec::Polyveck::default();
        let mut t1 = t.clone();
        polyvec::k_power2round(&mut t1, &mut t0);

        // Pack public key
        let mut pk_packed = [0u8; PUBLIC_KEY_SIZE];
        packing::pack_pk(&mut pk_packed, &rho, &t1);

        // Compute TR = SHAKE256(pk)
        let mut tr = [0u8; TR_SIZE];
        let mut h_tr = fips202::KeccakState::default();
        fips202::shake256_absorb(&mut h_tr, &pk_packed, pk_packed.len());
        fips202::shake256_finalize(&mut h_tr);
        fips202::shake256_squeeze(&mut tr, TR_SIZE, &mut h_tr);

        let public_key = PublicKey::new(pk_packed, tr);

        // Generate a deterministic key for this party
        let mut party_key = [0u8; 32];
        {
            let mut state = fips202::KeccakState::default();
            fips202::shake256_absorb(&mut state, &rho, 32);
            fips202::shake256_absorb(&mut state, &[my_id], 1);
            if let Some(session_id) = &self.state_data.round1.combined_session_id {
                fips202::shake256_absorb(&mut state, session_id, SESSION_ID_SIZE);
            }
            fips202::shake256_finalize(&mut state);
            fips202::shake256_squeeze(&mut party_key, 32, &mut state);
        }

        let private_share = PrivateKeyShare::new(
            my_id,
            parties,
            threshold,
            party_key,
            rho,
            tr,
            combined_shares,
        );

        Ok(DkgOutput {
            public_key,
            private_share,
        })
    }

    /// Hash the public key for consensus verification.
    fn hash_public_key(&self, public_key: &crate::keys::PublicKey) -> [u8; COMMITMENT_HASH_SIZE] {
        use qp_rusty_crystals_dilithium::fips202;

        let mut state = fips202::KeccakState::default();
        fips202::shake256_absorb(&mut state, public_key.as_bytes(), public_key.as_bytes().len());
        fips202::shake256_finalize(&mut state);

        let mut hash = [0u8; COMMITMENT_HASH_SIZE];
        fips202::shake256_squeeze(&mut hash, COMMITMENT_HASH_SIZE, &mut state);

        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ThresholdConfig;

    fn make_test_config(party_id: u8) -> DkgConfig {
        let threshold_config = ThresholdConfig::new(2, 3).unwrap();
        DkgConfig::new(threshold_config, party_id, vec![0, 1, 2]).unwrap()
    }

    #[test]
    fn test_dkg_creation() {
        let config = make_test_config(0);
        let dkg = DilithiumDkg::new(config, [0u8; 32]);

        assert!(matches!(dkg.state(), DkgState::Initialized));
        assert_eq!(dkg.my_party_id(), 0);
    }

    #[test]
    fn test_dkg_round1_generation() {
        let config = make_test_config(0);
        let mut dkg = DilithiumDkg::new(config, [0u8; 32]);

        // First poke should transition to Round1Generating and generate message
        let action = dkg.poke().unwrap();
        assert!(matches!(action, Action::SendMany(_)));

        // Second poke should transition to waiting
        let action = dkg.poke().unwrap();
        assert!(matches!(action, Action::Wait));
        assert!(matches!(dkg.state(), DkgState::Round1Waiting));
    }

    #[test]
    fn test_dkg_message_processing() {
        let config = make_test_config(0);
        let mut dkg = DilithiumDkg::new(config, [0u8; 32]);

        // Start round 1
        let _ = dkg.poke().unwrap();
        let _ = dkg.poke().unwrap();

        // Should be waiting
        assert!(matches!(dkg.state(), DkgState::Round1Waiting));

        // Receive messages from other parties
        let msg1 = DkgMessage::Round1(DkgRound1Broadcast {
            party_id: 1,
            session_id_contribution: [1u8; 32],
        });
        let msg2 = DkgMessage::Round1(DkgRound1Broadcast {
            party_id: 2,
            session_id_contribution: [2u8; 32],
        });

        // Use custom serialization for test
        let data1 = serialize_test_message(&msg1);
        let data2 = serialize_test_message(&msg2);

        dkg.message(1, data1);
        dkg.message(2, data2);

        // Should be able to advance now
        let action = dkg.poke().unwrap();
        assert!(matches!(action, Action::SendMany(_)));
    }

    #[test]
    fn test_subset_computation() {
        let config = make_test_config(0);
        let dkg = DilithiumDkg::new(config, [0u8; 32]);

        // For 2-of-3, subset size is 3 - 2 + 1 = 2
        // Party 0 should be in subsets: {0,1}, {0,2}
        let subsets = dkg.compute_subsets_for_party(0, 2, 3);
        assert_eq!(subsets.len(), 2);
        assert!(subsets.contains(&0b011)); // Party 0 and 1
        assert!(subsets.contains(&0b101)); // Party 0 and 2
    }

    fn serialize_test_message(msg: &DkgMessage) -> Vec<u8> {
        let mut buf = Vec::new();
        match msg {
            DkgMessage::Round1(m) => {
                buf.push(1u8);
                buf.push(m.party_id);
                buf.extend_from_slice(&m.session_id_contribution);
            }
            _ => unimplemented!(),
        }
        buf
    }
}
