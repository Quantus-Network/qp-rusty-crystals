//! Hash addresses (FIPS 205 section 4.2).

pub(crate) const WOTS_HASH: u32 = 0;
pub(crate) const WOTS_PK: u32 = 1;
pub(crate) const TREE: u32 = 2;
pub(crate) const FORS_TREE: u32 = 3;
pub(crate) const FORS_ROOTS: u32 = 4;
pub(crate) const WOTS_PRF: u32 = 5;
pub(crate) const FORS_PRF: u32 = 6;

#[derive(Clone, Copy, Default)]
pub(crate) struct Adrs([u8; 32]);

impl Adrs {
	fn set_word(&mut self, offset: usize, value: u32) {
		self.0[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
	}

	pub(crate) fn set_layer(&mut self, layer: u32) {
		self.set_word(0, layer);
	}

	pub(crate) fn set_tree(&mut self, tree: u64) {
		self.0[8..16].copy_from_slice(&tree.to_be_bytes());
	}

	pub(crate) fn set_type_and_clear(&mut self, kind: u32) {
		self.set_word(16, kind);
		self.0[20..].fill(0);
	}

	pub(crate) fn set_keypair(&mut self, keypair: u32) {
		self.set_word(20, keypair);
	}

	pub(crate) fn keypair(&self) -> u32 {
		u32::from_be_bytes([self.0[20], self.0[21], self.0[22], self.0[23]])
	}

	pub(crate) fn set_chain(&mut self, chain: u32) {
		self.set_word(24, chain);
	}

	pub(crate) fn set_tree_height(&mut self, height: u32) {
		self.set_word(24, height);
	}

	pub(crate) fn set_hash(&mut self, hash: u32) {
		self.set_word(28, hash);
	}

	pub(crate) fn set_tree_index(&mut self, index: u32) {
		self.set_word(28, index);
	}

	pub(crate) fn bytes(&self) -> &[u8; 32] {
		&self.0
	}

	/// The 22-byte `ADRSc` of the SHA-2 instantiations.
	pub(crate) fn compressed(&self) -> [u8; 22] {
		let mut out = [0u8; 22];
		out[0] = self.0[3];
		out[1..9].copy_from_slice(&self.0[8..16]);
		out[9..].copy_from_slice(&self.0[19..]);
		out
	}
}
