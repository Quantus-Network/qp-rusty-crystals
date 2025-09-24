#![allow(dead_code)]

use std::num::ParseIntError;

#[derive(Debug, Clone)]
pub struct TestVector {
	pub count: u32,
	pub seed: Vec<u8>,
	pub mlen: usize,
	pub msg: Vec<u8>,
	pub pk: Vec<u8>,
	pub sk: Vec<u8>,
	pub smlen: usize,
	pub sm: Vec<u8>,
}

impl TestVector {
	fn new(
		count: u32,
		seed: Vec<u8>,
		mlen: usize,
		msg: Vec<u8>,
		pk: Vec<u8>,
		sk: Vec<u8>,
		smlen: usize,
		sm: Vec<u8>,
	) -> Self {
		#[allow(clippy::too_many_arguments)]
		TestVector { count, seed, mlen, msg, pk, sk, smlen, sm }
	}

	// Method to extract signature including nonce from sm
	pub fn extract_signature(&self) -> &[u8] {
		// The total length of the signature including the nonce is smlen - mlen
		let signature_len = self.smlen - self.mlen;
		&self.sm[..signature_len]
	}
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, ParseIntError> {
	(0..hex.len())
		.step_by(2)
		.map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
		.collect()
}

pub fn parse_test_vectors(input: &str) -> Vec<TestVector> {
	let mut test_vectors = Vec::new();
	let mut lines = input.lines();

	while let Some(line) = lines.next() {
		if line.starts_with("count = ") {
			let count = line.split_whitespace().nth(2).unwrap().parse::<u32>().unwrap();
			let seed =
				hex_to_bytes(lines.next().unwrap().split_whitespace().nth(2).unwrap()).unwrap();
			let mlen = lines
				.next()
				.unwrap()
				.split_whitespace()
				.nth(2)
				.unwrap()
				.parse::<usize>()
				.unwrap();
			let msg =
				hex_to_bytes(lines.next().unwrap().split_whitespace().nth(2).unwrap()).unwrap();

			let pk =
				hex_to_bytes(lines.next().unwrap().split_whitespace().nth(2).unwrap()).unwrap();
			let sk =
				hex_to_bytes(lines.next().unwrap().split_whitespace().nth(2).unwrap()).unwrap();
			let smlen = lines
				.next()
				.unwrap()
				.split_whitespace()
				.nth(2)
				.unwrap()
				.parse::<usize>()
				.unwrap();
			let sm =
				hex_to_bytes(lines.next().unwrap().split_whitespace().nth(2).unwrap()).unwrap();

			test_vectors.push(TestVector::new(count, seed, mlen, msg, pk, sk, smlen, sm));
		}
	}

	test_vectors
}

#[cfg(test)]
mod tests {
	// Placeholder or actual test code here
}
