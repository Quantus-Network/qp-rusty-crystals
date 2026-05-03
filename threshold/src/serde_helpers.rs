//! Serde helpers for large arrays and polynomial vectors.
//!
//! Serde only supports arrays up to 32 elements by default.
//! These helpers provide serialization for larger fixed-size arrays
//! and polynomial vectors used in ML-DSA-87.

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Serde support for fixed-size byte arrays larger than 32 bytes.
#[cfg(feature = "serde")]
pub mod serde_byte_array {
	use super::*;

	pub fn serialize<S, const N: usize>(arr: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		arr.as_slice().serialize(serializer)
	}

	pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
	where
		D: Deserializer<'de>,
	{
		let vec: Vec<u8> = Vec::deserialize(deserializer)?;
		if vec.len() != N {
			return Err(serde::de::Error::custom(format!(
				"expected {} bytes, got {}",
				N,
				vec.len()
			)));
		}
		let mut arr = [0u8; N];
		arr.copy_from_slice(&vec);
		Ok(arr)
	}
}

/// Serde support for `Vec<[i32; 256]>` (polynomial vectors).
#[cfg(feature = "serde")]
pub mod serde_poly_vec {
	use super::*;

	pub fn serialize<S>(polys: &[[i32; 256]], serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		// Serialize as Vec<Vec<i32>> for compatibility
		let vec_of_vecs: Vec<Vec<i32>> = polys.iter().map(|arr| arr.to_vec()).collect();
		vec_of_vecs.serialize(serializer)
	}

	pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[i32; 256]>, D::Error>
	where
		D: Deserializer<'de>,
	{
		let vec_of_vecs: Vec<Vec<i32>> = Vec::deserialize(deserializer)?;
		vec_of_vecs
			.into_iter()
			.map(|v| {
				if v.len() != 256 {
					return Err(serde::de::Error::custom(format!(
						"expected 256 coefficients, got {}",
						v.len()
					)));
				}
				let mut arr = [0i32; 256];
				arr.copy_from_slice(&v);
				Ok(arr)
			})
			.collect()
	}
}

/// Serde support for `BTreeMap<u16, Vec<[i32; 256]>>` (partial-PK polynomial vectors).
#[cfg(feature = "serde")]
pub mod serde_partial_pks {
	use super::*;
	use std::collections::BTreeMap;

	pub fn serialize<S>(
		map: &BTreeMap<u16, Vec<[i32; 256]>>,
		serializer: S,
	) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let entries: Vec<(u16, Vec<Vec<i32>>)> = map
			.iter()
			.map(|(k, polys)| (*k, polys.iter().map(|arr| arr.to_vec()).collect()))
			.collect();
		entries.serialize(serializer)
	}

	pub fn deserialize<'de, D>(
		deserializer: D,
	) -> Result<BTreeMap<u16, Vec<[i32; 256]>>, D::Error>
	where
		D: Deserializer<'de>,
	{
		let entries: Vec<(u16, Vec<Vec<i32>>)> = Vec::deserialize(deserializer)?;
		entries
			.into_iter()
			.map(|(k, polys)| {
				let arrs: Result<Vec<[i32; 256]>, D::Error> = polys
					.into_iter()
					.map(|v| {
						if v.len() != 256 {
							return Err(serde::de::Error::custom(format!(
								"expected 256 coefficients, got {}",
								v.len()
							)));
						}
						let mut arr = [0i32; 256];
						arr.copy_from_slice(&v);
						Ok(arr)
					})
					.collect();
				arrs.map(|arrs| (k, arrs))
			})
			.collect()
	}
}

/// Serde support for `BTreeMap<u16, T>` where T is serializable.
/// BTreeMap provides deterministic iteration order (sorted by key),
/// ensuring consistent serialization output.
#[cfg(feature = "serde")]
pub mod serde_u16_btreemap {
	use super::*;
	use std::collections::BTreeMap;

	pub fn serialize<S, T>(map: &BTreeMap<u16, T>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
		T: Serialize,
	{
		// BTreeMap iterates in sorted key order, so output is deterministic
		let vec: Vec<(u16, &T)> = map.iter().map(|(k, v)| (*k, v)).collect();
		vec.serialize(serializer)
	}

	pub fn deserialize<'de, D, T>(deserializer: D) -> Result<BTreeMap<u16, T>, D::Error>
	where
		D: Deserializer<'de>,
		T: Deserialize<'de>,
	{
		let vec: Vec<(u16, T)> = Vec::deserialize(deserializer)?;
		Ok(vec.into_iter().collect())
	}
}

/// Serde support for `ParticipantList`.
#[cfg(feature = "serde")]
pub mod serde_participant_list {
	use super::*;
	use crate::participants::{ParticipantId, ParticipantList};

	pub fn serialize<S>(list: &ParticipantList, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		// Serialize as Vec<ParticipantId> (the sorted list)
		list.as_slice().serialize(serializer)
	}

	pub fn deserialize<'de, D>(deserializer: D) -> Result<ParticipantList, D::Error>
	where
		D: Deserializer<'de>,
	{
		let vec: Vec<ParticipantId> = Vec::deserialize(deserializer)?;
		ParticipantList::new(&vec)
			.ok_or_else(|| serde::de::Error::custom("duplicate participant IDs in ParticipantList"))
	}
}
