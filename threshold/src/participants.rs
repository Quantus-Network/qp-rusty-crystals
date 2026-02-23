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

use std::collections::HashMap;

/// Type alias for participant identifiers.
///
/// This is a u32 to match NEAR's `ParticipantId` type directly.
/// The actual values can be arbitrary (not necessarily sequential).
pub type ParticipantId = u32;

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
#[derive(Debug, Clone)]
pub struct ParticipantList {
	/// Sorted list of participant IDs
	participants: Vec<ParticipantId>,
	/// Maps participant ID to index in the sorted list
	indices: HashMap<ParticipantId, usize>,
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
	/// `Some(ParticipantList)` if all IDs are unique, `None` if duplicates exist.
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
		let mut sorted = participants.to_vec();
		sorted.sort();

		// Build index mapping
		let indices: HashMap<_, _> =
			sorted.iter().enumerate().map(|(idx, &id)| (id, idx)).collect();

		// Check for duplicates (HashMap will have fewer entries if duplicates exist)
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
	pub fn from_sorted(sorted_participants: Vec<ParticipantId>) -> Option<Self> {
		// Verify sorted and unique
		for i in 1..sorted_participants.len() {
			if sorted_participants[i] <= sorted_participants[i - 1] {
				return None;
			}
		}

		let indices: HashMap<_, _> =
			sorted_participants.iter().enumerate().map(|(idx, &id)| (id, idx)).collect();

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
	type IntoIter = std::iter::Copied<std::slice::Iter<'a, ParticipantId>>;

	fn into_iter(self) -> Self::IntoIter {
		self.participants.iter().copied()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

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
}
