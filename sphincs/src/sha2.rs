//! SHA-256 and SHA-512 over the `sha2` compression functions, with states
//! that are wiped on drop and can resume from a precomputed first block.

use sha2::digest::generic_array::GenericArray;
use zeroize::{Zeroize, ZeroizeOnDrop};

macro_rules! hasher {
	($name:ident, $word:ty, $block:literal, $length:ty, $compress:path, $iv:expr) => {
		#[derive(Zeroize, ZeroizeOnDrop)]
		pub(crate) struct $name {
			state: [$word; 8],
			block: [u8; $block],
			pos: usize,
			absorbed: u64,
		}

		impl $name {
			pub(crate) const BLOCK_BYTES: usize = $block;
			pub(crate) const OUTPUT_BYTES: usize = 8 * size_of::<$word>();

			pub(crate) fn new() -> Self {
				Self { state: $iv, block: [0; $block], pos: 0, absorbed: 0 }
			}

			pub(crate) fn restart(&mut self) {
				self.resume(&$iv, 0);
			}

			pub(crate) fn resume(&mut self, state: &[$word; 8], absorbed: u64) {
				self.state = *state;
				self.pos = 0;
				self.absorbed = absorbed;
			}

			pub(crate) fn state_after(block: &[u8; $block]) -> [$word; 8] {
				let mut state = $iv;
				$compress(&mut state, core::slice::from_ref(GenericArray::from_slice(block)));
				state
			}

			pub(crate) fn update(&mut self, mut data: &[u8]) {
				self.absorbed += data.len() as u64;
				while !data.is_empty() {
					let take = data.len().min($block - self.pos);
					self.block[self.pos..self.pos + take].copy_from_slice(&data[..take]);
					self.pos += take;
					data = &data[take..];
					if self.pos == $block {
						self.compress();
					}
				}
			}

			fn compress(&mut self) {
				$compress(
					&mut self.state,
					core::slice::from_ref(GenericArray::from_slice(&self.block)),
				);
				self.pos = 0;
			}

			/// Writes the leading `out.len()` digest bytes.
			pub(crate) fn finalize(&mut self, out: &mut [u8]) {
				const LENGTH_BYTES: usize = size_of::<$length>();
				let bits = <$length>::from(self.absorbed) * 8;
				self.block[self.pos] = 0x80;
				self.pos += 1;
				if self.pos > $block - LENGTH_BYTES {
					self.block[self.pos..].fill(0);
					self.compress();
				}
				self.block[self.pos..$block - LENGTH_BYTES].fill(0);
				self.block[$block - LENGTH_BYTES..].copy_from_slice(&bits.to_be_bytes());
				self.compress();
				for (chunk, word) in out.chunks_mut(size_of::<$word>()).zip(self.state) {
					chunk.copy_from_slice(&word.to_be_bytes()[..chunk.len()]);
				}
			}
		}
	};
}

hasher!(
	Sha256,
	u32,
	64,
	u64,
	sha2::compress256,
	[
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
		0x5be0cd19,
	]
);

hasher!(
	Sha512,
	u64,
	128,
	u128,
	sha2::compress512,
	[
		0x6a09e667f3bcc908,
		0xbb67ae8584caa73b,
		0x3c6ef372fe94f82b,
		0xa54ff53a5f1d36f1,
		0x510e527fade682d1,
		0x9b05688c2b3e6c1f,
		0x1f83d9abfb41bd6b,
		0x5be0cd19137e2179,
	]
);

#[cfg(test)]
mod tests {
	use super::*;
	use sha2::Digest;

	#[test]
	fn matches_the_sha2_crate() {
		let data: [u8; 300] = core::array::from_fn(|i| (i * 7 + 3) as u8);
		for len in 0..data.len() {
			let split = len / 3;
			let mut h256 = Sha256::new();
			h256.update(&data[..split]);
			h256.update(&data[split..len]);
			let mut out256 = [0u8; 32];
			h256.finalize(&mut out256);
			assert_eq!(out256[..], sha2::Sha256::digest(&data[..len])[..], "SHA-256 len {len}");

			let mut h512 = Sha512::new();
			h512.update(&data[..split]);
			h512.update(&data[split..len]);
			let mut out512 = [0u8; 64];
			h512.finalize(&mut out512);
			assert_eq!(out512[..], sha2::Sha512::digest(&data[..len])[..], "SHA-512 len {len}");
		}
	}

	#[test]
	fn resumes_from_a_first_block_state() {
		let data: [u8; 200] = core::array::from_fn(|i| i as u8);

		let mut h256 = Sha256::new();
		h256.resume(&Sha256::state_after(data[..64].try_into().unwrap()), 64);
		h256.update(&data[64..]);
		let mut out256 = [0u8; 20];
		h256.finalize(&mut out256);
		assert_eq!(out256[..], sha2::Sha256::digest(data)[..20]);

		let mut h512 = Sha512::new();
		h512.resume(&Sha512::state_after(data[..128].try_into().unwrap()), 128);
		h512.update(&data[128..]);
		let mut out512 = [0u8; 64];
		h512.finalize(&mut out512);
		assert_eq!(out512[..], sha2::Sha512::digest(data)[..]);

		h512.restart();
		h512.update(&data);
		h512.finalize(&mut out512);
		assert_eq!(out512[..], sha2::Sha512::digest(data)[..]);
	}
}
