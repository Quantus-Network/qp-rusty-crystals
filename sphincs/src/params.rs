//! The twelve FIPS 205 parameter sets (Table 2).

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum HashFamily {
	Shake,
	Sha2,
}

pub(crate) const LG_W: u32 = 4;
pub(crate) const W_MAX: u32 = (1 << LG_W) - 1;
const WOTS_LEN2: usize = 3;

pub(crate) const MAX_N: usize = 32;
pub(crate) const MAX_WOTS_LEN: usize = 2 * MAX_N + WOTS_LEN2;
pub(crate) const MAX_FORS_TREES: usize = 35;
pub(crate) const MAX_TREE_HEIGHT: usize = 14;
pub(crate) const MAX_DIGEST_BYTES: usize = 49;

pub(crate) struct Params {
	pub(crate) name: &'static str,
	pub(crate) hash: HashFamily,
	pub(crate) n: usize,
	pub(crate) h: usize,
	pub(crate) d: usize,
	pub(crate) hp: usize,
	pub(crate) a: usize,
	pub(crate) k: usize,
	pub(crate) m: usize,
}

impl Params {
	pub(crate) const fn wots_len(&self) -> usize {
		2 * self.n + WOTS_LEN2
	}

	pub(crate) const fn fors_sig_bytes(&self) -> usize {
		self.k * (1 + self.a) * self.n
	}

	pub(crate) const fn xmss_sig_bytes(&self) -> usize {
		(self.wots_len() + self.hp) * self.n
	}

	pub(crate) const fn sig_bytes(&self) -> usize {
		self.n + self.fors_sig_bytes() + self.d * self.xmss_sig_bytes()
	}
}

macro_rules! params {
	($ident:ident, $name:literal, $hash:ident, $n:literal, $h:literal, $d:literal, $hp:literal, $a:literal, $k:literal, $m:literal) => {
		pub(crate) const $ident: Params = Params {
			name: $name,
			hash: HashFamily::$hash,
			n: $n,
			h: $h,
			d: $d,
			hp: $hp,
			a: $a,
			k: $k,
			m: $m,
		};
	};
}

params!(SHA2_128S, "SLH-DSA-SHA2-128s", Sha2, 16, 63, 7, 9, 12, 14, 30);
params!(SHAKE_128S, "SLH-DSA-SHAKE-128s", Shake, 16, 63, 7, 9, 12, 14, 30);
params!(SHA2_128F, "SLH-DSA-SHA2-128f", Sha2, 16, 66, 22, 3, 6, 33, 34);
params!(SHAKE_128F, "SLH-DSA-SHAKE-128f", Shake, 16, 66, 22, 3, 6, 33, 34);
params!(SHA2_192S, "SLH-DSA-SHA2-192s", Sha2, 24, 63, 7, 9, 14, 17, 39);
params!(SHAKE_192S, "SLH-DSA-SHAKE-192s", Shake, 24, 63, 7, 9, 14, 17, 39);
params!(SHA2_192F, "SLH-DSA-SHA2-192f", Sha2, 24, 66, 22, 3, 8, 33, 42);
params!(SHAKE_192F, "SLH-DSA-SHAKE-192f", Shake, 24, 66, 22, 3, 8, 33, 42);
params!(SHA2_256S, "SLH-DSA-SHA2-256s", Sha2, 32, 64, 8, 8, 14, 22, 47);
params!(SHAKE_256S, "SLH-DSA-SHAKE-256s", Shake, 32, 64, 8, 8, 14, 22, 47);
params!(SHA2_256F, "SLH-DSA-SHA2-256f", Sha2, 32, 68, 17, 4, 9, 35, 49);
params!(SHAKE_256F, "SLH-DSA-SHAKE-256f", Shake, 32, 68, 17, 4, 9, 35, 49);

#[cfg(test)]
pub(crate) const ALL: [&Params; 12] = [
	&SHA2_128S,
	&SHAKE_128S,
	&SHA2_128F,
	&SHAKE_128F,
	&SHA2_192S,
	&SHAKE_192S,
	&SHA2_192F,
	&SHAKE_192F,
	&SHA2_256S,
	&SHAKE_256S,
	&SHA2_256F,
	&SHAKE_256F,
];

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn sizes_match_fips_205_table_2() {
		let sig_bytes =
			[7856, 7856, 17088, 17088, 16224, 16224, 35664, 35664, 29792, 29792, 49856, 49856];
		for (prm, expected) in ALL.iter().zip(sig_bytes) {
			assert_eq!(prm.sig_bytes(), expected, "{}", prm.name);
			assert_eq!(prm.h, prm.d * prm.hp, "{}", prm.name);
			let digest_bytes =
				(prm.k * prm.a).div_ceil(8) + (prm.h - prm.hp).div_ceil(8) + prm.hp.div_ceil(8);
			assert_eq!(prm.m, digest_bytes, "{}", prm.name);
			assert!(prm.n <= MAX_N && prm.k <= MAX_FORS_TREES && prm.m <= MAX_DIGEST_BYTES);
			assert!(prm.a <= MAX_TREE_HEIGHT && prm.hp <= MAX_TREE_HEIGHT);
			assert!(prm.h - prm.hp <= 64);
		}
	}
}
