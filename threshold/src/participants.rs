//! Participant management for threshold protocols.
//!
//! This module provides the `ParticipantList` type which manages a set of participants
//! and provides efficient ID-to-index mapping. This allows the threshold protocol to
//! accept arbitrary participant IDs (like NEAR's large u32 values) while internally
//! using sequential indices for bitmask operations and array indexing.
//!
//! # Design
//!
//! The design is modeled after the `threshold-signatures` library used by NEAR MPC
//! for EdDSA/ECDSA signatures. By handling the mapping internally, we eliminate the
//! need for a mapping layer in the integration code.
//!
//! # Example
//!
//! ```
//! use qp_rusty_crystals_threshold::participants::ParticipantList;
//!
//! // NEAR-style arbitrary participant IDs
//! let near_ids = vec![524342676, 1313390130, 3526595269];
//! let participants = ParticipantList::new(&near_ids).unwrap();
//!
//! // Get sequential index for bitmask operations
//! assert_eq!(participants.index_of(524342676), Some(0));  // smallest -> index 0
//! assert_eq!(participants.index_of(1313390130), Some(1));
//! assert_eq!(participants.index_of(3526595269), Some(2)); // largest -> index 2
//!
//! // Convert index back to participant ID
//! assert_eq!(participants.get(0), Some(524342676));
//! ```

use alloc::{collections::BTreeMap, vec::Vec};
use core::iter;

use borsh::{BorshDeserialize, BorshSerialize};
use zeroize::Zeroize;

use crate::error::MAX_PARTIES;

/// Type alias for participant identifiers.
///
/// This is a u32 to match NEAR's `ParticipantId` type directly.
/// The actual values can be arbitrary (not necessarily sequential).
pub type ParticipantId = u32;

/// Build the index map from a sorted participants vector.
fn build_indices(participants: &[ParticipantId]) -> BTreeMap<ParticipantId, usize> {
	participants.iter().enumerate().map(|(idx, &id)| (id, idx)).collect()
}

/// A sorted list of participants with efficient ID-to-index mapping.
///
/// This structure maintains a sorted list of participant IDs and provides
/// O(1) lookup from participant ID to sequential index. The sequential
/// indices (0, 1, 2, ...) are used internally for bitmask operations and
/// array indexing, while the original participant IDs are preserved for
/// message routing and identification.
///
/// # Invariants
///
/// - Participants are always stored in sorted order
/// - No duplicate participant IDs
/// - Index mapping is consistent: `index_of(get(i)) == Some(i)`
/// - Length is at most `MAX_PARTIES` (6)
///
/// # Serialization
///
/// Only the `participants` vector is serialized. The `indices` map is
/// recomputed during deserialization to prevent malformed indices from
/// being injected via untrusted serialized data.
#[derive(Debug, Clone)]
pub struct ParticipantList {
	/// Sorted list of participant IDs
	participants: Vec<ParticipantId>,
	/// Maps participant ID to index in the sorted list (cached, not serialized)
	indices: BTreeMap<ParticipantId, usize>,
}

impl BorshSerialize for ParticipantList {
	fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
		// Only serialize participants; indices is recomputed on deserialize
		self.participants.serialize(writer)
	}
}

impl BorshDeserialize for ParticipantList {
	fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
		let participants = Vec::<ParticipantId>::deserialize_reader(reader)?;

		// Validate invariants - use MAX_PARTIES to match protocol limits
		if participants.len() > MAX_PARTIES as usize {
			return Err(borsh::io::Error::new(
				borsh::io::ErrorKind::InvalidData,
				"ParticipantList exceeds MAX_PARTIES",
			));
		}

		// Verify sorted and unique (strictly increasing)
		for i in 1..participants.len() {
			if participants[i] <= participants[i - 1] {
				return Err(borsh::io::Error::new(
					borsh::io::ErrorKind::InvalidData,
					"ParticipantList is not sorted or contains duplicates",
				));
			}
		}

		// Build indices from validated participants
		let indices = build_indices(&participants);
		Ok(Self { participants, indices })
	}
}

impl Zeroize for ParticipantList {
	fn zeroize(&mut self) {
		self.participants.zeroize();
		self.indices.clear();
	}
}

impl ParticipantList {
	/// Create a new participant list from a slice of participant IDs.
	///
	/// The participants will be sorted internally. Returns `None` if
	/// there are duplicate participant IDs.
	///
	/// # Arguments
	///
	/// * `participants` - Slice of participant IDs (can be in any order)
	///
	/// # Returns
	///
	/// `Some(ParticipantList)` if all IDs are unique, `None` if duplicates exist
	/// or if there are more than `MAX_PARTIES` (6) participants.
	///
	/// # Example
	///
	/// ```
	/// use qp_rusty_crystals_threshold::participants::ParticipantList;
	///
	/// let list = ParticipantList::new(&[300, 100, 200]).unwrap();
	/// assert_eq!(list.len(), 3);
	/// assert_eq!(list.get(0), Some(100)); // sorted order
	/// ```
	pub fn new(participants: &[ParticipantId]) -> Option<Self> {
		// Check participant count limit (matches protocol's MAX_PARTIES)
		if participants.len() > MAX_PARTIES as usize {
			return None;
		}

		let mut sorted = participants.to_vec();
		sorted.sort();

		// Build index mapping
		let indices = build_indices(&sorted);

		// Check for duplicates (BTreeMap will have fewer entries if duplicates exist)
		if indices.len() != sorted.len() {
			return None;
		}

		Some(Self { participants: sorted, indices })
	}

	/// Create a participant list from an already-sorted vector.
	///
	/// This is an optimization for cases where the caller knows the
	/// participants are already sorted and unique.
	///
	/// # Safety
	///
	/// The caller must ensure that `sorted_participants` is sorted and
	/// contains no duplicates. If these invariants are violated, the
	/// behavior is unspecified but not unsafe in the memory sense.
	///
	/// Returns `None` if there are more than `MAX_PARTIES` (6) participants
	/// or if the list is not sorted/unique.
	pub fn from_sorted(sorted_participants: Vec<ParticipantId>) -> Option<Self> {
		// Check participant count limit (matches protocol's MAX_PARTIES)
		if sorted_participants.len() > MAX_PARTIES as usize {
			return None;
		}

		// Verify sorted and unique
		for i in 1..sorted_participants.len() {
			if sorted_participants[i] <= sorted_participants[i - 1] {
				return None;
			}
		}

		let indices = build_indices(&sorted_participants);
		Some(Self { participants: sorted_participants, indices })
	}

	/// Returns the number of participants.
	#[inline]
	pub fn len(&self) -> usize {
		self.participants.len()
	}

	/// Returns true if the list is empty.
	#[inline]
	pub fn is_empty(&self) -> bool {
		self.participants.is_empty()
	}

	/// Check if a participant ID is in this list.
	#[inline]
	pub fn contains(&self, id: ParticipantId) -> bool {
		self.indices.contains_key(&id)
	}

	/// Get the sequential index for a participant ID.
	///
	/// Returns `Some(index)` if the participant is in the list,
	/// `None` otherwise. The index is guaranteed to be in the
	/// range `0..self.len()`.
	///
	/// # Example
	///
	/// ```
	/// use qp_rusty_crystals_threshold::participants::ParticipantList;
	///
	/// let list = ParticipantList::new(&[1000, 500, 750]).unwrap();
	/// assert_eq!(list.index_of(500), Some(0));  // smallest
	/// assert_eq!(list.index_of(750), Some(1));
	/// assert_eq!(list.index_of(1000), Some(2)); // largest
	/// assert_eq!(list.index_of(999), None);     // not in list
	/// ```
	#[inline]
	pub fn index_of(&self, id: ParticipantId) -> Option<usize> {
		self.indices.get(&id).copied()
	}

	/// Get the participant ID at a given index.
	///
	/// Returns `Some(id)` if the index is valid, `None` otherwise.
	///
	/// # Example
	///
	/// ```
	/// use qp_rusty_crystals_threshold::participants::ParticipantList;
	///
	/// let list = ParticipantList::new(&[1000, 500, 750]).unwrap();
	/// assert_eq!(list.get(0), Some(500));
	/// assert_eq!(list.get(1), Some(750));
	/// assert_eq!(list.get(2), Some(1000));
	/// assert_eq!(list.get(3), None);
	/// ```
	#[inline]
	pub fn get(&self, index: usize) -> Option<ParticipantId> {
		self.participants.get(index).copied()
	}

	/// Iterate over all participant IDs in sorted order.
	pub fn iter(&self) -> impl Iterator<Item = ParticipantId> + '_ {
		self.participants.iter().copied()
	}

	/// Iterate over all participant IDs except the given one.
	///
	/// Useful for getting "other participants" when sending messages.
	///
	/// # Example
	///
	/// ```
	/// use qp_rusty_crystals_threshold::participants::ParticipantList;
	///
	/// let list = ParticipantList::new(&[1, 2, 3]).unwrap();
	/// let others: Vec<_> = list.others(2).collect();
	/// assert_eq!(others, vec![1, 3]);
	/// ```
	pub fn others(&self, me: ParticipantId) -> impl Iterator<Item = ParticipantId> + '_ {
		self.participants.iter().copied().filter(move |&id| id != me)
	}

	/// Get a slice of all participant IDs in sorted order.
	#[inline]
	pub fn as_slice(&self) -> &[ParticipantId] {
		&self.participants
	}

	/// Convert a bitmask of indices to a list of participant IDs.
	///
	/// The bitmask uses bit position `i` to represent the participant
	/// at index `i` in this list.
	///
	/// # Example
	///
	/// ```
	/// use qp_rusty_crystals_threshold::participants::ParticipantList;
	///
	/// let list = ParticipantList::new(&[100, 200, 300]).unwrap();
	/// // Bitmask 0b101 = indices 0 and 2 = participants 100 and 300
	/// let ids = list.ids_from_mask(0b101);
	/// assert_eq!(ids, vec![100, 300]);
	/// ```
	pub fn ids_from_mask(&self, mask: u16) -> Vec<ParticipantId> {
		let mut result = Vec::new();
		for (idx, &id) in self.participants.iter().enumerate() {
			if mask & (1 << idx) != 0 {
				result.push(id);
			}
		}
		result
	}

	/// Convert a list of participant IDs to a bitmask of indices.
	///
	/// Unknown participant IDs are ignored.
	///
	/// # Example
	///
	/// ```
	/// use qp_rusty_crystals_threshold::participants::ParticipantList;
	///
	/// let list = ParticipantList::new(&[100, 200, 300]).unwrap();
	/// let mask = list.mask_from_ids(&[100, 300]);
	/// assert_eq!(mask, 0b101); // indices 0 and 2
	/// ```
	pub fn mask_from_ids(&self, ids: &[ParticipantId]) -> u16 {
		let mut mask: u16 = 0;
		for &id in ids {
			if let Some(idx) = self.index_of(id) {
				mask |= 1 << idx;
			}
		}
		mask
	}

	/// Check if a participant is included in a subset bitmask.
	///
	/// Returns `true` if the participant's index bit is set in the mask.
	/// Returns `false` if the participant is not in this list or their bit is not set.
	///
	/// # Example
	///
	/// ```
	/// use qp_rusty_crystals_threshold::participants::ParticipantList;
	///
	/// let list = ParticipantList::new(&[100, 200, 300]).unwrap();
	/// // Bitmask 0b101 = indices 0 and 2 = participants 100 and 300
	/// assert!(list.is_in_mask(100, 0b101));
	/// assert!(!list.is_in_mask(200, 0b101));
	/// assert!(list.is_in_mask(300, 0b101));
	/// assert!(!list.is_in_mask(999, 0b101)); // not in list
	/// ```
	pub fn is_in_mask(&self, party: ParticipantId, mask: u16) -> bool {
		if let Some(idx) = self.index_of(party) {
			(mask & (1 << idx)) != 0
		} else {
			false
		}
	}

	/// Check if this list contains all the given participant IDs.
	pub fn contains_all(&self, ids: &[ParticipantId]) -> bool {
		ids.iter().all(|id| self.contains(*id))
	}

	/// Create a subset of this participant list containing only the given IDs.
	///
	/// Returns `None` if any of the IDs are not in this list.
	///
	/// # Example
	///
	/// ```
	/// use qp_rusty_crystals_threshold::participants::ParticipantList;
	///
	/// let list = ParticipantList::new(&[100, 200, 300, 400]).unwrap();
	/// let subset = list.subset(&[100, 300]).unwrap();
	/// assert_eq!(subset.len(), 2);
	/// assert_eq!(subset.get(0), Some(100));
	/// assert_eq!(subset.get(1), Some(300));
	/// ```
	pub fn subset(&self, ids: &[ParticipantId]) -> Option<Self> {
		// Verify all IDs exist in this list
		if !self.contains_all(ids) {
			return None;
		}
		ParticipantList::new(ids)
	}
}

impl PartialEq for ParticipantList {
	fn eq(&self, other: &Self) -> bool {
		self.participants == other.participants
	}
}

impl Eq for ParticipantList {}

impl From<ParticipantList> for Vec<ParticipantId> {
	fn from(list: ParticipantList) -> Self {
		list.participants
	}
}

impl<'a> IntoIterator for &'a ParticipantList {
	type Item = ParticipantId;
	type IntoIter = iter::Copied<core::slice::Iter<'a, ParticipantId>>;

	fn into_iter(self) -> Self::IntoIter {
		self.participants.iter().copied()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::vec;

	#[test]
	fn test_new_sorts_participants() {
		let list = ParticipantList::new(&[300, 100, 200]).unwrap();
		assert_eq!(list.as_slice(), &[100, 200, 300]);
	}

	#[test]
	fn test_new_rejects_duplicates() {
		let result = ParticipantList::new(&[100, 200, 100]);
		assert!(result.is_none());
	}

	#[test]
	fn test_index_of() {
		let list = ParticipantList::new(&[1000, 500, 750]).unwrap();
		assert_eq!(list.index_of(500), Some(0));
		assert_eq!(list.index_of(750), Some(1));
		assert_eq!(list.index_of(1000), Some(2));
		assert_eq!(list.index_of(999), None);
	}

	#[test]
	fn test_get() {
		let list = ParticipantList::new(&[1000, 500, 750]).unwrap();
		assert_eq!(list.get(0), Some(500));
		assert_eq!(list.get(1), Some(750));
		assert_eq!(list.get(2), Some(1000));
		assert_eq!(list.get(3), None);
	}

	#[test]
	fn test_index_get_roundtrip() {
		let list = ParticipantList::new(&[524342676, 1313390130, 3526595269]).unwrap();
		for &id in list.as_slice() {
			let idx = list.index_of(id).unwrap();
			assert_eq!(list.get(idx), Some(id));
		}
	}

	#[test]
	fn test_others() {
		let list = ParticipantList::new(&[1, 2, 3]).unwrap();
		let others: Vec<_> = list.others(2).collect();
		assert_eq!(others, vec![1, 3]);
	}

	#[test]
	fn test_mask_roundtrip() {
		let list = ParticipantList::new(&[100, 200, 300, 400]).unwrap();

		// Test mask -> ids -> mask roundtrip
		let original_mask: u16 = 0b1010; // indices 1 and 3 = 200 and 400
		let ids = list.ids_from_mask(original_mask);
		assert_eq!(ids, vec![200, 400]);
		let recovered_mask = list.mask_from_ids(&ids);
		assert_eq!(recovered_mask, original_mask);
	}

	#[test]
	fn test_subset() {
		let list = ParticipantList::new(&[100, 200, 300, 400]).unwrap();

		let subset = list.subset(&[400, 200]).unwrap(); // order doesn't matter
		assert_eq!(subset.len(), 2);
		assert_eq!(subset.as_slice(), &[200, 400]); // sorted

		// Subset indices are relative to the subset, not the original
		assert_eq!(subset.index_of(200), Some(0));
		assert_eq!(subset.index_of(400), Some(1));
	}

	#[test]
	fn test_subset_invalid() {
		let list = ParticipantList::new(&[100, 200, 300]).unwrap();
		let result = list.subset(&[100, 999]); // 999 not in list
		assert!(result.is_none());
	}

	#[test]
	fn test_near_style_ids() {
		// Test with realistic NEAR participant IDs
		let near_ids = vec![524342676, 1313390130, 3526595269, 3731869668];
		let list = ParticipantList::new(&near_ids).unwrap();

		assert_eq!(list.len(), 4);

		// Verify sorted order
		assert_eq!(list.get(0), Some(524342676));
		assert_eq!(list.get(1), Some(1313390130));
		assert_eq!(list.get(2), Some(3526595269));
		assert_eq!(list.get(3), Some(3731869668));

		// Index lookup works
		assert_eq!(list.index_of(524342676), Some(0));
		assert_eq!(list.index_of(3731869668), Some(3));
	}

	#[test]
	fn test_empty_list() {
		let list = ParticipantList::new(&[]).unwrap();
		assert!(list.is_empty());
		assert_eq!(list.len(), 0);
		assert_eq!(list.get(0), None);
		assert_eq!(list.index_of(0), None);
	}

	#[test]
	fn test_single_participant() {
		let list = ParticipantList::new(&[42]).unwrap();
		assert_eq!(list.len(), 1);
		assert_eq!(list.get(0), Some(42));
		assert_eq!(list.index_of(42), Some(0));
		assert!(list.others(42).next().is_none());
	}

	#[test]
	fn test_from_sorted() {
		let sorted = vec![100, 200, 300];
		let list = ParticipantList::from_sorted(sorted).unwrap();
		assert_eq!(list.as_slice(), &[100, 200, 300]);

		// Should reject unsorted
		let unsorted = vec![200, 100, 300];
		assert!(ParticipantList::from_sorted(unsorted).is_none());

		// Should reject duplicates
		let with_dups = vec![100, 100, 200];
		assert!(ParticipantList::from_sorted(with_dups).is_none());
	}

	#[test]
	fn test_contains() {
		let list = ParticipantList::new(&[100, 200, 300]).unwrap();
		assert!(list.contains(100));
		assert!(list.contains(200));
		assert!(list.contains(300));
		assert!(!list.contains(150));
		assert!(!list.contains(0));
	}

	#[test]
	fn test_contains_all() {
		let list = ParticipantList::new(&[100, 200, 300, 400]).unwrap();
		assert!(list.contains_all(&[100, 300]));
		assert!(list.contains_all(&[200]));
		assert!(list.contains_all(&[]));
		assert!(!list.contains_all(&[100, 999]));
	}

	#[test]
	fn test_iter() {
		let list = ParticipantList::new(&[300, 100, 200]).unwrap();
		let collected: Vec<_> = list.iter().collect();
		assert_eq!(collected, vec![100, 200, 300]); // sorted
	}

	#[test]
	fn test_into_iter() {
		let list = ParticipantList::new(&[300, 100, 200]).unwrap();
		let collected: Vec<_> = (&list).into_iter().collect();
		assert_eq!(collected, vec![100, 200, 300]);
	}

	#[test]
	fn test_equality() {
		let list1 = ParticipantList::new(&[300, 100, 200]).unwrap();
		let list2 = ParticipantList::new(&[100, 200, 300]).unwrap();
		let list3 = ParticipantList::new(&[100, 200, 400]).unwrap();

		assert_eq!(list1, list2); // same participants, different input order
		assert_ne!(list1, list3); // different participants
	}

	#[test]
	fn test_into_vec() {
		let list = ParticipantList::new(&[300, 100, 200]).unwrap();
		let vec: Vec<ParticipantId> = list.into();
		assert_eq!(vec, vec![100, 200, 300]);
	}

	#[test]
	fn test_rejects_too_many_participants() {
		// MAX_PARTIES is 6 - the protocol limit
		let too_many: Vec<ParticipantId> = (0..7).collect();
		assert!(ParticipantList::new(&too_many).is_none());

		// Exactly 6 should work
		let exactly_max: Vec<ParticipantId> = (0..6).collect();
		assert!(ParticipantList::new(&exactly_max).is_some());
	}

	#[test]
	fn test_from_sorted_rejects_too_many_participants() {
		let too_many: Vec<ParticipantId> = (0..7).collect();
		assert!(ParticipantList::from_sorted(too_many).is_none());

		let exactly_max: Vec<ParticipantId> = (0..6).collect();
		assert!(ParticipantList::from_sorted(exactly_max).is_some());
	}

	#[test]
	fn test_borsh_roundtrip() {
		let list = ParticipantList::new(&[300, 100, 200]).unwrap();
		let serialized = borsh::to_vec(&list).unwrap();
		let deserialized: ParticipantList = borsh::from_slice(&serialized).unwrap();
		assert_eq!(list, deserialized);
	}

	#[test]
	fn test_borsh_rejects_unsorted() {
		// Manually craft a serialized unsorted list
		// Vec<u32> serialization: 4-byte length prefix + 4 bytes per element
		let unsorted: Vec<ParticipantId> = vec![200, 100, 300];
		let serialized = borsh::to_vec(&unsorted).unwrap();

		let result: Result<ParticipantList, _> = borsh::from_slice(&serialized);
		assert!(result.is_err(), "Should reject unsorted participants");
	}

	#[test]
	fn test_borsh_rejects_duplicates() {
		// Manually craft a serialized list with duplicates
		let with_dups: Vec<ParticipantId> = vec![100, 100, 200];
		let serialized = borsh::to_vec(&with_dups).unwrap();

		let result: Result<ParticipantList, _> = borsh::from_slice(&serialized);
		assert!(result.is_err(), "Should reject duplicate participants");
	}

	#[test]
	fn test_borsh_rejects_too_many() {
		// Manually craft a serialized list with too many participants
		let too_many: Vec<ParticipantId> = (0..17).collect();
		let serialized = borsh::to_vec(&too_many).unwrap();

		let result: Result<ParticipantList, _> = borsh::from_slice(&serialized);
		assert!(result.is_err(), "Should reject too many participants");
	}

	#[test]
	fn test_serialization_only_includes_participants() {
		// Verify that only the participants vector is serialized (not indices)
		let list = ParticipantList::new(&[100, 200, 300]).unwrap();
		let serialized = borsh::to_vec(&list).unwrap();

		// A Vec<u32> with 3 elements: 4 bytes length + 3*4 bytes = 16 bytes
		assert_eq!(serialized.len(), 16);

		// Should match serialization of just the participants vector
		let just_vec: Vec<ParticipantId> = vec![100, 200, 300];
		let vec_serialized = borsh::to_vec(&just_vec).unwrap();
		assert_eq!(serialized, vec_serialized);
	}
}
