//! The hash functions of FIPS 205 section 11, for both hash families.

use qp_rusty_crystals_dilithium::fips202::{
	shake256_absorb, shake256_finalize, shake256_squeeze, Shake256State,
};
use zeroize::Zeroizing;

use crate::{
	adrs::Adrs,
	params::{HashFamily, Params},
	sha2::{Sha256, Sha512},
};

#[derive(Clone, Copy)]
enum Engine {
	Shake,
	Sha256,
	Sha512,
}

/// Key material and hash states of one operation. The states absorb secret
/// key material and are wiped on drop.
pub(crate) struct Hasher<'a> {
	pub(crate) prm: &'static Params,
	sk_seed: &'a [u8],
	sk_prf: &'a [u8],
	pk_seed: &'a [u8],
	pk_root: &'a [u8],
	seeded256: [u32; 8],
	seeded512: [u64; 8],
	sha256: Sha256,
	sha512: Sha512,
	shake: Shake256State,
}

impl<'a> Hasher<'a> {
	/// Parts an operation does not use are passed as empty slices.
	pub(crate) fn new(
		prm: &'static Params,
		sk_seed: &'a [u8],
		sk_prf: &'a [u8],
		pk_seed: &'a [u8],
		pk_root: &'a [u8],
	) -> Self {
		let mut block256 = [0u8; Sha256::BLOCK_BYTES];
		block256[..prm.n].copy_from_slice(pk_seed);
		let mut block512 = [0u8; Sha512::BLOCK_BYTES];
		block512[..prm.n].copy_from_slice(pk_seed);
		Self {
			prm,
			sk_seed,
			sk_prf,
			pk_seed,
			pk_root,
			seeded256: Sha256::state_after(&block256),
			seeded512: Sha512::state_after(&block512),
			sha256: Sha256::new(),
			sha512: Sha512::new(),
			shake: Shake256State::default(),
		}
	}

	/// `wide` selects SHA-512 in the SHA-2 sets of categories 3 and 5.
	fn engine(&self, wide: bool) -> Engine {
		match self.prm.hash {
			HashFamily::Shake => Engine::Shake,
			HashFamily::Sha2 if wide && self.prm.n > 16 => Engine::Sha512,
			HashFamily::Sha2 => Engine::Sha256,
		}
	}

	fn restart(&mut self, engine: Engine) {
		match engine {
			Engine::Shake => self.shake.init(),
			Engine::Sha256 => self.sha256.restart(),
			Engine::Sha512 => self.sha512.restart(),
		}
	}

	fn absorb(&mut self, engine: Engine, data: &[u8]) {
		match engine {
			Engine::Shake => shake256_absorb(&mut self.shake, data),
			Engine::Sha256 => self.sha256.update(data),
			Engine::Sha512 => self.sha512.update(data),
		}
	}

	fn finish(&mut self, engine: Engine, out: &mut [u8]) {
		match engine {
			Engine::Shake => {
				shake256_finalize(&mut self.shake);
				shake256_squeeze(out, &mut self.shake);
			},
			Engine::Sha256 => self.sha256.finalize(out),
			Engine::Sha512 => self.sha512.finalize(out),
		}
	}

	fn start_tweak(&mut self, adrs: &Adrs, wide: bool) -> Engine {
		let engine = self.engine(wide);
		match engine {
			Engine::Shake => {
				self.shake.init();
				shake256_absorb(&mut self.shake, self.pk_seed);
				shake256_absorb(&mut self.shake, adrs.bytes());
			},
			Engine::Sha256 => {
				self.sha256.resume(&self.seeded256, Sha256::BLOCK_BYTES as u64);
				self.sha256.update(&adrs.compressed());
			},
			Engine::Sha512 => {
				self.sha512.resume(&self.seeded512, Sha512::BLOCK_BYTES as u64);
				self.sha512.update(&adrs.compressed());
			},
		}
		engine
	}

	pub(crate) fn f(&mut self, adrs: &Adrs, value: &mut [u8]) {
		let engine = self.start_tweak(adrs, false);
		self.absorb(engine, value);
		self.finish(engine, value);
	}

	pub(crate) fn prf(&mut self, adrs: &Adrs, out: &mut [u8]) {
		let engine = self.start_tweak(adrs, false);
		self.absorb(engine, self.sk_seed);
		self.finish(engine, out);
	}

	pub(crate) fn h(&mut self, adrs: &Adrs, node: &mut [u8], sibling: &[u8], node_is_left: bool) {
		let engine = self.start_tweak(adrs, true);
		if node_is_left {
			self.absorb(engine, node);
			self.absorb(engine, sibling);
		} else {
			self.absorb(engine, sibling);
			self.absorb(engine, node);
		}
		self.finish(engine, node);
	}

	pub(crate) fn t(&mut self, adrs: &Adrs, values: &[u8], out: &mut [u8]) {
		let engine = self.start_tweak(adrs, true);
		self.absorb(engine, values);
		self.finish(engine, out);
	}

	pub(crate) fn prf_msg(&mut self, opt_rand: &[u8], message: &[&[u8]], out: &mut [u8]) {
		let engine = self.engine(true);
		let (block_bytes, digest_bytes) = match engine {
			Engine::Shake => {
				self.restart(engine);
				self.absorb(engine, self.sk_prf);
				self.absorb_message(engine, opt_rand, message);
				return self.finish(engine, out);
			},
			Engine::Sha256 => (Sha256::BLOCK_BYTES, Sha256::OUTPUT_BYTES),
			Engine::Sha512 => (Sha512::BLOCK_BYTES, Sha512::OUTPUT_BYTES),
		};

		let mut pad = Zeroizing::new([0x36u8; Sha512::BLOCK_BYTES]);
		for (p, k) in pad.iter_mut().zip(self.sk_prf) {
			*p ^= k;
		}
		let mut inner = Zeroizing::new([0u8; Sha512::OUTPUT_BYTES]);
		let inner = &mut inner[..digest_bytes];
		self.restart(engine);
		self.absorb(engine, &pad[..block_bytes]);
		self.absorb_message(engine, opt_rand, message);
		self.finish(engine, inner);

		for p in pad.iter_mut() {
			*p ^= 0x36 ^ 0x5c;
		}
		self.restart(engine);
		self.absorb(engine, &pad[..block_bytes]);
		self.absorb(engine, inner);
		self.finish(engine, out);
	}

	pub(crate) fn h_msg(&mut self, r: &[u8], message: &[&[u8]], out: &mut [u8]) {
		let engine = self.engine(true);
		self.restart(engine);
		self.absorb(engine, r);
		self.absorb(engine, self.pk_seed);
		self.absorb_message(engine, self.pk_root, message);
		let digest_bytes = match engine {
			Engine::Shake => return self.finish(engine, out),
			Engine::Sha256 => Sha256::OUTPUT_BYTES,
			Engine::Sha512 => Sha512::OUTPUT_BYTES,
		};

		let mut digest = [0u8; Sha512::OUTPUT_BYTES];
		let digest = &mut digest[..digest_bytes];
		self.finish(engine, digest);
		let mut block = [0u8; Sha512::OUTPUT_BYTES];
		for (counter, chunk) in out.chunks_mut(digest_bytes).enumerate() {
			self.restart(engine);
			self.absorb(engine, r);
			self.absorb(engine, self.pk_seed);
			self.absorb(engine, digest);
			self.absorb(engine, &(counter as u32).to_be_bytes());
			self.finish(engine, &mut block[..digest_bytes]);
			chunk.copy_from_slice(&block[..chunk.len()]);
		}
	}

	fn absorb_message(&mut self, engine: Engine, first: &[u8], message: &[&[u8]]) {
		self.absorb(engine, first);
		for part in message {
			self.absorb(engine, part);
		}
	}
}
