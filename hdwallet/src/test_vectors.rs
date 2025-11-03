use crate::tests::TestVector;
#[cfg(test)]
use alloc::{boxed::Box, string::String, vec::Vec};
#[cfg(test)]
extern crate std;
#[cfg(test)]
use std::{fs::File, io::Read, path::Path};

#[cfg(test)]
pub fn load_known_private_keys(
	file_name: &str,
) -> Result<Vec<TestVector>, Box<dyn std::error::Error>> {
	let file_path = Path::new(file_name);
	let mut file = File::open(file_path)?;
	let mut contents = String::new();
	file.read_to_string(&mut contents)?;

	let vectors: Vec<TestVector> = serde_json::from_str(&contents)?;
	Ok(vectors)
}

pub fn str_to_64_bytes(s: &str) -> [u8; 64] {
	let mut bytes = [0u8; 64];
	hex::decode_to_slice(s, &mut bytes).unwrap();
	bytes
}

pub fn str_to_32_bytes(s: &str) -> [u8; 32] {
	let mut bytes = [0u8; 32];
	hex::decode_to_slice(s, &mut bytes).unwrap();
	bytes
}
