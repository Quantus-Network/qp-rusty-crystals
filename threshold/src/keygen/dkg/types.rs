//! Types for Distributed Key Generation (DKG) protocol.
//!
//! This module defines the message types exchanged during the 4-round DKG protocol,
//! as well as configuration and output types.

use std::collections::HashMap;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::config::ThresholdConfig;
use crate::keys::{PrivateKeyShare, PublicKey};

/// Participant identifier (0 to n-1).
pub type ParticipantId = u8;

/// Subset mask - a bitmask indicating which parties are in a subset.
/// Uses u16 to support up to 16 parties.
pub type SubsetMask = u16;

/// Size of session ID in bytes.
pub const SESSION_ID_SIZE: usize = 32;

/// Size of commitment hash in bytes.
pub const COMMITMENT_HASH_SIZE: usize = 32;

/// Size of rho contribution in bytes.
pub const RHO_CONTRIBUTION_SIZE: usize = 32;

// ML-DSA-87 parameters
/// Number of polynomials in s1 vector.
pub const L: usize = 7;
/// Number of polynomials in s2 vector.
pub const K: usize = 8;
/// Polynomial degree.
pub const N: usize = 256;

/// Configuration for the DKG protocol.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DkgConfig {
    /// The threshold configuration (t, n).
    pub threshold_config: ThresholdConfig,
    /// This party's identifier.
    pub my_party_id: ParticipantId,
    /// All participants in the DKG (sorted).
    pub all_participants: Vec<ParticipantId>,
}

impl DkgConfig {
    /// Create a new DKG configuration.
    ///
    /// # Arguments
    /// * `threshold_config` - The (t, n) threshold configuration
    /// * `my_party_id` - This party's identifier (0 to n-1)
    /// * `all_participants` - List of all participant IDs
    ///
    /// # Errors
    /// Returns an error if:
    /// - `my_party_id` is not in `all_participants`
    /// - `all_participants` length doesn't match `threshold_config.total_parties()`
    pub fn new(
        threshold_config: ThresholdConfig,
        my_party_id: ParticipantId,
        all_participants: Vec<ParticipantId>,
    ) -> Result<Self, &'static str> {
        if all_participants.len() != threshold_config.total_parties() as usize {
            return Err("participant count doesn't match threshold config");
        }
        if !all_participants.contains(&my_party_id) {
            return Err("my_party_id not in all_participants");
        }

        let mut sorted_participants = all_participants;
        sorted_participants.sort();

        Ok(Self {
            threshold_config,
            my_party_id,
            all_participants: sorted_participants,
        })
    }

    /// Get the threshold value (minimum parties to sign).
    pub fn threshold(&self) -> u8 {
        self.threshold_config.threshold()
    }

    /// Get the total number of parties.
    pub fn total_parties(&self) -> u8 {
        self.threshold_config.total_parties()
    }

    /// Get all participants except self.
    pub fn other_participants(&self) -> impl Iterator<Item = ParticipantId> + '_ {
        self.all_participants
            .iter()
            .copied()
            .filter(move |&p| p != self.my_party_id)
    }
}

/// Contribution for a single subset.
///
/// Contains the random η-bounded polynomial coefficients that this party
/// contributes to a specific subset's share.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SubsetContribution {
    /// Share of s1 polynomial vector (L polynomials, each with N coefficients).
    pub s1: Vec<[i32; N]>,
    /// Share of s2 polynomial vector (K polynomials, each with N coefficients).
    pub s2: Vec<[i32; N]>,
}

impl SubsetContribution {
    /// Create a new empty subset contribution.
    pub fn new() -> Self {
        Self {
            s1: vec![[0i32; N]; L],
            s2: vec![[0i32; N]; K],
        }
    }

    /// Check if all coefficients are within the η bound.
    pub fn verify_bounds(&self, eta: i32) -> bool {
        for poly in &self.s1 {
            for &coeff in poly {
                if coeff < -eta || coeff > eta {
                    return false;
                }
            }
        }
        for poly in &self.s2 {
            for &coeff in poly {
                if coeff < -eta || coeff > eta {
                    return false;
                }
            }
        }
        true
    }
}

impl Default for SubsetContribution {
    fn default() -> Self {
        Self::new()
    }
}

/// All contributions from one party for all subsets they belong to.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PartyContributions {
    /// The party that generated these contributions.
    pub party_id: ParticipantId,
    /// Random bytes contributed to the final rho seed.
    pub rho_contribution: [u8; RHO_CONTRIBUTION_SIZE],
    /// Contributions for each subset this party belongs to.
    /// Key is the subset mask (bitmask of party IDs in the subset).
    pub subset_contributions: HashMap<SubsetMask, SubsetContribution>,
}

impl PartyContributions {
    /// Create a new empty party contributions structure.
    pub fn new(party_id: ParticipantId) -> Self {
        Self {
            party_id,
            rho_contribution: [0u8; RHO_CONTRIBUTION_SIZE],
            subset_contributions: HashMap::new(),
        }
    }
}

// ============================================================================
// Round Messages
// ============================================================================

/// Round 1 message: Session ID contribution.
///
/// Each party contributes random bytes to form a unique session ID,
/// preventing replay attacks across different DKG runs.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DkgRound1Broadcast {
    /// The party sending this message.
    pub party_id: ParticipantId,
    /// Random bytes contributed to the session ID.
    pub session_id_contribution: [u8; SESSION_ID_SIZE],
}

/// Round 2 message: Commitment hash.
///
/// Each party broadcasts a hash of their contributions before revealing them.
/// This prevents parties from adapting their contributions based on others'.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DkgRound2Broadcast {
    /// The party sending this message.
    pub party_id: ParticipantId,
    /// Hash of (party_id || rho_contribution || all subset contributions).
    pub commitment_hash: [u8; COMMITMENT_HASH_SIZE],
}

/// Round 3 message: Revealed contributions.
///
/// Each party reveals their actual contributions. Other parties verify
/// that the hash matches what was committed in Round 2.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DkgRound3Broadcast {
    /// The party sending this message.
    pub party_id: ParticipantId,
    /// The actual contributions (must hash to the Round 2 commitment).
    pub contributions: PartyContributions,
}

/// Round 4 message: Confirmation.
///
/// Each party confirms they successfully computed their shares and
/// the public key. All parties must agree on the public key hash.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DkgRound4Broadcast {
    /// The party sending this message.
    pub party_id: ParticipantId,
    /// Whether this party succeeded in computing their share.
    pub success: bool,
    /// Hash of the computed public key (for consensus verification).
    pub public_key_hash: [u8; COMMITMENT_HASH_SIZE],
}

// ============================================================================
// Serialized Message Wrapper
// ============================================================================

/// Wrapper enum for all DKG message types.
///
/// This allows messages to be serialized/deserialized without knowing
/// the specific round at deserialization time.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DkgMessage {
    /// Round 1: Session ID contribution.
    Round1(DkgRound1Broadcast),
    /// Round 2: Commitment hash.
    Round2(DkgRound2Broadcast),
    /// Round 3: Revealed contributions.
    Round3(DkgRound3Broadcast),
    /// Round 4: Confirmation.
    Round4(DkgRound4Broadcast),
}

impl DkgMessage {
    /// Get the party ID of the sender.
    pub fn party_id(&self) -> ParticipantId {
        match self {
            DkgMessage::Round1(msg) => msg.party_id,
            DkgMessage::Round2(msg) => msg.party_id,
            DkgMessage::Round3(msg) => msg.party_id,
            DkgMessage::Round4(msg) => msg.party_id,
        }
    }

    /// Get the round number (1-4).
    pub fn round(&self) -> u8 {
        match self {
            DkgMessage::Round1(_) => 1,
            DkgMessage::Round2(_) => 2,
            DkgMessage::Round3(_) => 3,
            DkgMessage::Round4(_) => 4,
        }
    }
}

// ============================================================================
// Output Types
// ============================================================================

/// Output of a successful DKG protocol run.
///
/// This contains everything needed to participate in threshold signing.
#[derive(Debug, Clone)]
pub struct DkgOutput {
    /// The threshold public key (shared by all parties).
    pub public_key: PublicKey,
    /// This party's private key share.
    pub private_share: PrivateKeyShare,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dkg_config_creation() {
        let threshold_config = ThresholdConfig::new(2, 3).unwrap();
        let config = DkgConfig::new(threshold_config, 1, vec![0, 1, 2]);

        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.threshold(), 2);
        assert_eq!(config.total_parties(), 3);
        assert_eq!(config.my_party_id, 1);
    }

    #[test]
    fn test_dkg_config_invalid_party_id() {
        let threshold_config = ThresholdConfig::new(2, 3).unwrap();
        let config = DkgConfig::new(threshold_config, 5, vec![0, 1, 2]);

        assert!(config.is_err());
    }

    #[test]
    fn test_dkg_config_wrong_participant_count() {
        let threshold_config = ThresholdConfig::new(2, 3).unwrap();
        let config = DkgConfig::new(threshold_config, 0, vec![0, 1]);

        assert!(config.is_err());
    }

    #[test]
    fn test_dkg_config_other_participants() {
        let threshold_config = ThresholdConfig::new(2, 3).unwrap();
        let config = DkgConfig::new(threshold_config, 1, vec![0, 1, 2]).unwrap();

        let others: Vec<_> = config.other_participants().collect();
        assert_eq!(others, vec![0, 2]);
    }

    #[test]
    fn test_subset_contribution_bounds() {
        let mut contrib = SubsetContribution::new();
        assert!(contrib.verify_bounds(2));

        // Set a coefficient outside bounds
        contrib.s1[0][0] = 5;
        assert!(!contrib.verify_bounds(2));
        assert!(contrib.verify_bounds(5));
    }

    #[test]
    fn test_dkg_message_party_id() {
        let msg = DkgMessage::Round1(DkgRound1Broadcast {
            party_id: 2,
            session_id_contribution: [0u8; 32],
        });
        assert_eq!(msg.party_id(), 2);
        assert_eq!(msg.round(), 1);
    }
}
