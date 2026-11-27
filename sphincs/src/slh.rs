//! WOTS+, XMSS, the hypertree, FORS and the internal SLH-DSA functions
//! (FIPS 205 algorithms 4 to 20).

use crate::{
	adrs::{Adrs, FORS_PRF, FORS_ROOTS, FORS_TREE, TREE, WOTS_HASH, WOTS_PK, WOTS_PRF},
	hash::Hasher,
	params::{
		Params, LG_W, MAX_DIGEST_BYTES, MAX_FORS_TREES, MAX_N, MAX_TREE_HEIGHT, MAX_WOTS_LEN, W_MAX,
	},
};

#[derive(Clone, Copy)]
enum Tree {
	Xmss,
	Fors,
}

fn base_2b(x: &[u8], b: u32, out: &mut [u32]) {
	let mut bytes = x.iter();
	let mut bits = 0;
	let mut total = 0u32;
	for digit in out {
		while bits < b {
			total = (total << 8) | u32::from(*bytes.next().expect("input covers all digits"));
			bits += 8;
		}
		bits -= b;
		*digit = (total >> bits) & ((1 << b) - 1);
	}
}

fn wots_digits(prm: &Params, message: &[u8], digits: &mut [u32]) {
	let (message_digits, checksum_digits) = digits.split_at_mut(2 * prm.n);
	base_2b(message, LG_W, message_digits);
	let checksum: u32 = message_digits.iter().map(|digit| W_MAX - digit).sum();
	base_2b(&((checksum << 4) as u16).to_be_bytes(), LG_W, checksum_digits);
}

fn to_int(bytes: &[u8]) -> u64 {
	bytes.iter().fold(0, |total, byte| (total << 8) | u64::from(*byte))
}

fn split_digest<'d>(prm: &Params, digest: &'d [u8]) -> (&'d [u8], u64, u32) {
	let (md, rest) = digest.split_at((prm.k * prm.a).div_ceil(8));
	let (tree, leaf) = rest.split_at((prm.h - prm.hp).div_ceil(8));
	let tree_bits = prm.h - prm.hp;
	let idx_tree = to_int(tree) & (u64::MAX >> (64 - tree_bits));
	let idx_leaf = to_int(leaf) & ((1 << prm.hp) - 1);
	(md, idx_tree, idx_leaf as u32)
}

impl Hasher<'_> {
	fn chain(&mut self, adrs: &mut Adrs, value: &mut [u8], start: u32, steps: u32) {
		for position in start..start + steps {
			adrs.set_hash(position);
			self.f(adrs, value);
		}
	}

	fn wots_secret(&mut self, adrs: &Adrs, chain: u32, out: &mut [u8]) {
		let mut sk_adrs = *adrs;
		sk_adrs.set_type_and_clear(WOTS_PRF);
		sk_adrs.set_keypair(adrs.keypair());
		sk_adrs.set_chain(chain);
		self.prf(&sk_adrs, out);
	}

	fn wots_compress(&mut self, adrs: &Adrs, chain_ends: &[u8], out: &mut [u8]) {
		let mut pk_adrs = *adrs;
		pk_adrs.set_type_and_clear(WOTS_PK);
		pk_adrs.set_keypair(adrs.keypair());
		self.t(&pk_adrs, chain_ends, out);
	}

	fn wots_pk_gen(&mut self, adrs: &mut Adrs, out: &mut [u8]) {
		let n = self.prm.n;
		let mut chain_ends = [0u8; MAX_WOTS_LEN * MAX_N];
		let chain_ends = &mut chain_ends[..self.prm.wots_len() * n];
		for (chain, value) in chain_ends.chunks_exact_mut(n).enumerate() {
			self.wots_secret(adrs, chain as u32, value);
			adrs.set_chain(chain as u32);
			self.chain(adrs, value, 0, W_MAX);
		}
		self.wots_compress(adrs, chain_ends, out);
	}

	fn wots_sign(&mut self, adrs: &mut Adrs, message: &[u8], sig: &mut [u8]) {
		let mut digits = [0u32; MAX_WOTS_LEN];
		wots_digits(self.prm, message, &mut digits[..self.prm.wots_len()]);
		for (chain, value) in sig.chunks_exact_mut(self.prm.n).enumerate() {
			self.wots_secret(adrs, chain as u32, value);
			adrs.set_chain(chain as u32);
			self.chain(adrs, value, 0, digits[chain]);
		}
	}

	/// `node` holds the signed message on entry and the public key on return.
	fn wots_pk_from_sig(&mut self, adrs: &mut Adrs, sig: &[u8], node: &mut [u8]) {
		let n = self.prm.n;
		let mut digits = [0u32; MAX_WOTS_LEN];
		wots_digits(self.prm, node, &mut digits[..self.prm.wots_len()]);
		let mut chain_ends = [0u8; MAX_WOTS_LEN * MAX_N];
		let chain_ends = &mut chain_ends[..sig.len()];
		chain_ends.copy_from_slice(sig);
		for (chain, value) in chain_ends.chunks_exact_mut(n).enumerate() {
			adrs.set_chain(chain as u32);
			self.chain(adrs, value, digits[chain], W_MAX - digits[chain]);
		}
		self.wots_compress(adrs, chain_ends, node);
	}

	fn fors_secret(&mut self, adrs: &Adrs, index: u32, out: &mut [u8]) {
		let mut sk_adrs = *adrs;
		sk_adrs.set_type_and_clear(FORS_PRF);
		sk_adrs.set_keypair(adrs.keypair());
		sk_adrs.set_tree_index(index);
		self.prf(&sk_adrs, out);
	}

	fn leaf(&mut self, tree: Tree, adrs: &mut Adrs, index: u32, out: &mut [u8]) {
		match tree {
			Tree::Xmss => {
				adrs.set_type_and_clear(WOTS_HASH);
				adrs.set_keypair(index);
				self.wots_pk_gen(adrs, out);
			},
			Tree::Fors => {
				self.fors_secret(adrs, index, out);
				adrs.set_tree_height(0);
				adrs.set_tree_index(index);
				self.f(adrs, out);
			},
		}
	}

	/// Node `index` at `height` of an XMSS or FORS tree (`xmss_node`, `fors_node`).
	fn node(&mut self, tree: Tree, adrs: &mut Adrs, index: u32, height: u32, out: &mut [u8]) {
		let n = self.prm.n;
		let mut left_nodes = [[0u8; MAX_N]; MAX_TREE_HEIGHT];
		let first_leaf = index << height;
		for offset in 0..1u32 << height {
			let leaf = first_leaf + offset;
			self.leaf(tree, adrs, leaf, out);
			let mut level = 0;
			while (offset >> level) & 1 == 1 {
				if matches!(tree, Tree::Xmss) {
					adrs.set_type_and_clear(TREE);
				}
				adrs.set_tree_height(level + 1);
				adrs.set_tree_index(leaf >> (level + 1));
				self.h(adrs, out, &left_nodes[level as usize][..n], false);
				level += 1;
			}
			if level < height {
				left_nodes[level as usize][..n].copy_from_slice(out);
			}
		}
	}

	/// Walks an authentication path from `node` at `leaf` up to the root.
	fn climb(&mut self, adrs: &mut Adrs, leaf: u32, auth: &[u8], node: &mut [u8]) {
		for (level, sibling) in auth.chunks_exact(self.prm.n).enumerate() {
			adrs.set_tree_height(level as u32 + 1);
			adrs.set_tree_index(leaf >> (level + 1));
			self.h(adrs, node, sibling, (leaf >> level) & 1 == 0);
		}
	}

	fn xmss_sign(&mut self, adrs: &mut Adrs, message: &[u8], leaf: u32, sig: &mut [u8]) {
		let n = self.prm.n;
		let (wots_sig, auth) = sig.split_at_mut(self.prm.wots_len() * n);
		for (level, sibling) in auth.chunks_exact_mut(n).enumerate() {
			self.node(Tree::Xmss, adrs, (leaf >> level) ^ 1, level as u32, sibling);
		}
		adrs.set_type_and_clear(WOTS_HASH);
		adrs.set_keypair(leaf);
		self.wots_sign(adrs, message, wots_sig);
	}

	/// `node` holds the signed message on entry and the tree root on return.
	fn xmss_pk_from_sig(&mut self, adrs: &mut Adrs, leaf: u32, sig: &[u8], node: &mut [u8]) {
		let (wots_sig, auth) = sig.split_at(self.prm.wots_len() * self.prm.n);
		adrs.set_type_and_clear(WOTS_HASH);
		adrs.set_keypair(leaf);
		self.wots_pk_from_sig(adrs, wots_sig, node);
		adrs.set_type_and_clear(TREE);
		self.climb(adrs, leaf, auth, node);
	}

	fn layer_adrs(&self, layer: usize, tree: &mut u64, leaf: &mut u32) -> Adrs {
		if layer > 0 {
			*leaf = (*tree & ((1 << self.prm.hp) - 1)) as u32;
			*tree >>= self.prm.hp;
		}
		let mut adrs = Adrs::default();
		adrs.set_layer(layer as u32);
		adrs.set_tree(*tree);
		adrs
	}

	/// `node` holds the FORS public key on entry and `PK.root` on return.
	fn ht_sign(&mut self, node: &mut [u8], mut tree: u64, mut leaf: u32, sig: &mut [u8]) {
		let layers = sig.chunks_exact_mut(self.prm.xmss_sig_bytes());
		for (layer, xmss_sig) in layers.enumerate() {
			let mut adrs = self.layer_adrs(layer, &mut tree, &mut leaf);
			self.xmss_sign(&mut adrs, node, leaf, xmss_sig);
			self.xmss_pk_from_sig(&mut adrs, leaf, xmss_sig, node);
		}
	}

	/// `node` holds the FORS public key on entry and the hypertree root on return.
	fn ht_root(&mut self, node: &mut [u8], mut tree: u64, mut leaf: u32, sig: &[u8]) {
		let layers = sig.chunks_exact(self.prm.xmss_sig_bytes());
		for (layer, xmss_sig) in layers.enumerate() {
			let mut adrs = self.layer_adrs(layer, &mut tree, &mut leaf);
			self.xmss_pk_from_sig(&mut adrs, leaf, xmss_sig, node);
		}
	}

	fn fors_sign(&mut self, adrs: &mut Adrs, md: &[u8], sig: &mut [u8]) {
		let (n, a) = (self.prm.n, self.prm.a as u32);
		let mut indices = [0u32; MAX_FORS_TREES];
		base_2b(md, a, &mut indices[..self.prm.k]);
		for (tree, tree_sig) in sig.chunks_exact_mut((1 + self.prm.a) * n).enumerate() {
			let (secret, auth) = tree_sig.split_at_mut(n);
			let (tree, index) = (tree as u32, indices[tree]);
			self.fors_secret(adrs, (tree << a) + index, secret);
			for (level, sibling) in auth.chunks_exact_mut(n).enumerate() {
				let level = level as u32;
				let position = (tree << (a - level)) + ((index >> level) ^ 1);
				self.node(Tree::Fors, adrs, position, level, sibling);
			}
		}
	}

	fn fors_pk_from_sig(&mut self, adrs: &mut Adrs, sig: &[u8], md: &[u8], out: &mut [u8]) {
		let (n, a) = (self.prm.n, self.prm.a as u32);
		let mut indices = [0u32; MAX_FORS_TREES];
		base_2b(md, a, &mut indices[..self.prm.k]);
		let mut roots = [0u8; MAX_FORS_TREES * MAX_N];
		let roots = &mut roots[..self.prm.k * n];
		let tree_sigs = sig.chunks_exact((1 + self.prm.a) * n);
		for (tree, (tree_sig, root)) in tree_sigs.zip(roots.chunks_exact_mut(n)).enumerate() {
			let (secret, auth) = tree_sig.split_at(n);
			let leaf = ((tree as u32) << a) + indices[tree];
			root.copy_from_slice(secret);
			adrs.set_tree_height(0);
			adrs.set_tree_index(leaf);
			self.f(adrs, root);
			self.climb(adrs, leaf, auth, root);
		}
		let mut pk_adrs = *adrs;
		pk_adrs.set_type_and_clear(FORS_ROOTS);
		pk_adrs.set_keypair(adrs.keypair());
		self.t(&pk_adrs, roots, out);
	}
}

fn fors_adrs(tree: u64, leaf: u32) -> Adrs {
	let mut adrs = Adrs::default();
	adrs.set_tree(tree);
	adrs.set_type_and_clear(FORS_TREE);
	adrs.set_keypair(leaf);
	adrs
}

/// `slh_keygen_internal`. `seed` is `SK.seed || SK.prf || PK.seed`; `sk`
/// receives `seed || PK.root`.
pub(crate) fn keygen(prm: &'static Params, seed: &[u8], sk: &mut [u8]) {
	let n = prm.n;
	let mut root = [0u8; MAX_N];
	let mut hasher = Hasher::new(prm, &seed[..n], &[], &seed[2 * n..], &[]);
	let mut adrs = Adrs::default();
	adrs.set_layer(prm.d as u32 - 1);
	hasher.node(Tree::Xmss, &mut adrs, 0, prm.hp as u32, &mut root[..n]);
	sk[..3 * n].copy_from_slice(seed);
	sk[3 * n..].copy_from_slice(&root[..n]);
}

/// `slh_sign_internal`. `message` is the concatenation of its parts.
pub(crate) fn sign(
	prm: &'static Params,
	sk: &[u8],
	message: &[&[u8]],
	addrnd: Option<&[u8]>,
	sig: &mut [u8],
) {
	let n = prm.n;
	let (sk_seed, rest) = sk.split_at(n);
	let (sk_prf, rest) = rest.split_at(n);
	let (pk_seed, pk_root) = rest.split_at(n);
	let mut hasher = Hasher::new(prm, sk_seed, sk_prf, pk_seed, pk_root);

	let (r, rest) = sig.split_at_mut(n);
	let (fors_sig, ht_sig) = rest.split_at_mut(prm.fors_sig_bytes());
	hasher.prf_msg(addrnd.unwrap_or(pk_seed), message, r);
	let mut digest = [0u8; MAX_DIGEST_BYTES];
	hasher.h_msg(r, message, &mut digest[..prm.m]);
	let (md, tree, leaf) = split_digest(prm, &digest[..prm.m]);

	let mut adrs = fors_adrs(tree, leaf);
	hasher.fors_sign(&mut adrs, md, fors_sig);
	let mut node = [0u8; MAX_N];
	hasher.fors_pk_from_sig(&mut adrs, fors_sig, md, &mut node[..n]);
	hasher.ht_sign(&mut node[..n], tree, leaf, ht_sig);
	assert!(node[..n] == *pk_root, "signature does not verify under the public key");
}

/// `slh_verify_internal`.
pub(crate) fn verify(prm: &'static Params, pk: &[u8], message: &[&[u8]], sig: &[u8]) -> bool {
	let n = prm.n;
	if sig.len() != prm.sig_bytes() {
		return false;
	}
	let (pk_seed, pk_root) = pk.split_at(n);
	let mut hasher = Hasher::new(prm, &[], &[], pk_seed, pk_root);

	let (r, rest) = sig.split_at(n);
	let (fors_sig, ht_sig) = rest.split_at(prm.fors_sig_bytes());
	let mut digest = [0u8; MAX_DIGEST_BYTES];
	hasher.h_msg(r, message, &mut digest[..prm.m]);
	let (md, tree, leaf) = split_digest(prm, &digest[..prm.m]);

	let mut adrs = fors_adrs(tree, leaf);
	let mut node = [0u8; MAX_N];
	hasher.fors_pk_from_sig(&mut adrs, fors_sig, md, &mut node[..n]);
	hasher.ht_root(&mut node[..n], tree, leaf, ht_sig);
	node[..n] == *pk_root
}
