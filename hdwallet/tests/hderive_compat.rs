//! Compatibility tests for `hderive`.
//!
//! Wallets derive their keys through this module, so a change in any derived
//! secret, or in which paths are accepted, changes user addresses. Every
//! expected value here was recorded from qp-rusty-crystals-hdwallet 4.1.1.
//!
//! Paths are hardened-only: lattice keys have no public derivation, so every
//! level must carry the `'` marker and any other spelling is rejected.

use std::str::FromStr;

use hex_literal::hex;
use qp_rusty_crystals_hdwallet::hderive::{ChildNumber, DerivationPath, Error, ExtendedPrivKey};
use sha2::{Digest, Sha512};

const SEED_64: [u8; 64] = hex!(
	"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
);
const SEED_16: [u8; 16] = [0xa5; 16];
const SEED_32: [u8; 32] = hex!("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0");

const DEEPEST_PATH: &str = "m/1'/2'/3'/4'/5'/6'/7'/8'/9'/10'/11'/12'/13'/14'/15'/16'";

const KNOWN_ANSWERS: &[(&[u8], &str, [u8; 32])] = &[
	(&SEED_64, "m", hex!("5752ce5b3f276b7bfe395b17c339a5bbbd0481343406240f114f40b688ce2208")),
	(&SEED_64, "m/0'", hex!("23f016bac7a0b51746f22232247a7639ded4ec0f00a15a1448ba63069164f676")),
	(
		&SEED_64,
		"m/2147483647'",
		hex!("c51eae570613be91ddb135bc64a67ec82990c31821596ed5306bf2650efab7c2"),
	),
	(
		&SEED_64,
		"m/44'/189189'/0'/0'/0'",
		hex!("8f8fdf525fb1ee93339bbbc5ad2431fffca6bf93aed65f54373acfc58297c6e7"),
	),
	(
		&SEED_64,
		DEEPEST_PATH,
		hex!("ea83381697bb44ee810fbb59d8a77093abbc6f5f5ca900e992bf2f36290d3748"),
	),
	(&SEED_16, "m", hex!("b4c2ef858319b50fa046c7ba7d47b3de4c1873dfa694cb071625db4f8901e6b5")),
	(&SEED_16, "m/0'", hex!("07496f216236e675f8bcac739dd4be03ccf345e9318e9afb914ca67e744a04f8")),
	(
		&SEED_16,
		"m/2147483647'",
		hex!("d1d1d44d0767e754469ada2f9e8daab4bded9e4658d56974b96db5b7b0572931"),
	),
	(
		&SEED_16,
		"m/44'/189189'/0'/0'/0'",
		hex!("bf27058ac6c07a29db158735c617d419e6e93835cbe4aced262d034ef69e3f9e"),
	),
	(
		&SEED_16,
		DEEPEST_PATH,
		hex!("31c4a906df10f8efbba2a5a0377cdaf1dfd60f3286c006fbd14b8f65f229781f"),
	),
	(&SEED_32, "m", hex!("b8ac273ad07cc13c7e8bb874492da9f7062a6f1f7e9e8bfdcfdf49316ffcb7c5")),
	(&SEED_32, "m/0'", hex!("f49f69e041bef43d18d395929365bb4dded3e38c1481528a52e70eab08710b8f")),
	(
		&SEED_32,
		"m/2147483647'",
		hex!("55856365ea1a81be5de196becf5f7335c5ebb5529ec8324f74dc0d584c5be454"),
	),
	(
		&SEED_32,
		"m/44'/189189'/0'/0'/0'",
		hex!("a9e69781266732e6cd98d9d94f53572d12982800477be8d4f819b1d8f467f154"),
	),
	(
		&SEED_32,
		DEEPEST_PATH,
		hex!("460ac57a568a4a45de3fe58b6c059492b064c340feecb5ca9fdec0c7d509b7c1"),
	),
];

const ACCEPTED_PATHS: &[&str] = &[
	"m",
	"m/0'",
	"m/1'",
	"m/10'",
	"m/2147483647'",
	"m/44'/189189'/0'/0'/0'",
	"m/44'/189189189'/0'/0'/0'",
	DEEPEST_PATH,
];

const REJECTED_PATHS: &[(&str, Error)] = &[
	// A level without the hardened marker, at any position.
	("m/0", Error::NotHardened),
	("m/44", Error::NotHardened),
	("m/44/0'", Error::NotHardened),
	("m/44'/0", Error::NotHardened),
	("m/44'/189189'/0'/0/0", Error::NotHardened),
	("m/44'/189189'/0'/0'/0", Error::NotHardened),
	("m/44'/189189'/0/0'/0'", Error::NotHardened),
	// Other notations for "hardened" are not the marker.
	("m/0h", Error::NotHardened),
	("m/0H", Error::NotHardened),
	("m/0\u{2019}", Error::NotHardened),
	("m/0`", Error::NotHardened),
	("m/0\"", Error::NotHardened),
	// Empty levels.
	("m/", Error::NotHardened),
	("m//0'", Error::NotHardened),
	("m/0'/", Error::NotHardened),
	("m/m", Error::NotHardened),
	// The first failing level decides.
	("m/1/+1'", Error::NotHardened),
	("m/+1'/1", Error::InvalidChildNumber),
	// Hardened, but not a canonical decimal index below 2^31.
	("m/'", Error::InvalidChildNumber),
	("m/0''", Error::InvalidChildNumber),
	("m/00'", Error::InvalidChildNumber),
	("m/01'", Error::InvalidChildNumber),
	("m/044'", Error::InvalidChildNumber),
	("m/+1'", Error::InvalidChildNumber),
	("m/-1'", Error::InvalidChildNumber),
	("m/ 1'", Error::InvalidChildNumber),
	("m/1 '", Error::InvalidChildNumber),
	("m/1_0'", Error::InvalidChildNumber),
	("m/0x1'", Error::InvalidChildNumber),
	("m/\u{ff11}'", Error::InvalidChildNumber),
	("m/2147483648'", Error::InvalidChildNumber),
	("m/4294967295'", Error::InvalidChildNumber),
	("m/4294967296'", Error::InvalidChildNumber),
	("m/99999999999999999999'", Error::InvalidChildNumber),
	("m/44'/2147483648'/0'", Error::InvalidChildNumber),
	// Not rooted at exactly `m`.
	("", Error::InvalidDerivationPath),
	("M", Error::InvalidDerivationPath),
	("M/0'", Error::InvalidDerivationPath),
	(" m", Error::InvalidDerivationPath),
	("m ", Error::InvalidDerivationPath),
	(" m/0'", Error::InvalidDerivationPath),
	("m /0'", Error::InvalidDerivationPath),
	("/m/0'", Error::InvalidDerivationPath),
	("m'", Error::InvalidDerivationPath),
	("m'/0'", Error::InvalidDerivationPath),
	("0'", Error::InvalidDerivationPath),
	("44'/0'", Error::InvalidDerivationPath),
	("mm/0'", Error::InvalidDerivationPath),
	("abc", Error::InvalidDerivationPath),
	("1/a/2", Error::InvalidDerivationPath),
	// Bounds are checked before the syntax.
	("m/0'/0'/0'/0'/0'/0'/0'/0'/0'/0'/0'/0'/0'/0'/0'/0'/0'", Error::PathTooDeep(17)),
	("x/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0", Error::PathTooDeep(17)),
];

fn derive(seed: &[u8], path: &str) -> Result<[u8; 32], Error> {
	let mut key = ExtendedPrivKey::zeroed();
	ExtendedPrivKey::derive(seed, path, &mut key)?;
	Ok(*key.secret().as_bytes())
}

#[test]
fn derived_secrets_match_recorded_values() {
	for (seed, path, expected) in KNOWN_ANSWERS {
		assert_eq!(
			derive(seed, path).as_ref(),
			Ok(expected),
			"seed of {} bytes at {path}",
			seed.len()
		);
	}
}

#[test]
fn only_hardened_canonical_paths_are_accepted() {
	for path in ACCEPTED_PATHS {
		assert!(DerivationPath::from_str(path).is_ok(), "{path:?} must parse");
		assert!(derive(&SEED_64, path).is_ok(), "{path:?} must derive");
	}

	let mut key = ExtendedPrivKey::zeroed();
	ExtendedPrivKey::derive(&SEED_64, "m/5'/6'", &mut key).unwrap();
	let before = *key.secret().as_bytes();
	for &(path, ref error) in REJECTED_PATHS {
		assert_eq!(DerivationPath::from_str(path).unwrap_err(), *error, "parsing {path:?}");
		// The path error wins over a seed error, and a failed call leaves the key alone.
		for seed in [&SEED_64[..], &[7u8; 5][..]] {
			assert_eq!(
				ExtendedPrivKey::derive(seed, path, &mut key).unwrap_err(),
				*error,
				"deriving at {path:?}"
			);
		}
		assert_eq!(key.secret().as_bytes(), &before, "{path:?} modified the output key");
	}

	let too_long = format!("m/{}'", "1".repeat(254));
	assert_eq!(too_long.len(), 257);
	assert_eq!(DerivationPath::from_str(&too_long).unwrap_err(), Error::PathTooLong(257));
	assert_eq!(derive(&SEED_64, &too_long).unwrap_err(), Error::PathTooLong(257));
}

#[test]
fn child_steps_match_full_path_derivation() {
	for (parent, child) in [("m", "0'"), ("m/44'", "189189'"), ("m/3'/2147483647'", "7'")] {
		let mut stepped = ExtendedPrivKey::zeroed();
		ExtendedPrivKey::derive(&SEED_64, parent, &mut stepped).unwrap();
		stepped.child_in_place(ChildNumber::from_str(child).unwrap());
		assert_eq!(
			stepped.secret().as_bytes(),
			&derive(&SEED_64, &format!("{parent}/{child}")).unwrap(),
			"{parent} stepped by {child}"
		);
	}

	for (child, error) in [
		("0", Error::NotHardened),
		("", Error::NotHardened),
		("m", Error::NotHardened),
		("'", Error::InvalidChildNumber),
		("00'", Error::InvalidChildNumber),
		("+0'", Error::InvalidChildNumber),
		("2147483648'", Error::InvalidChildNumber),
	] {
		assert_eq!(ChildNumber::from_str(child).unwrap_err(), error, "child number {child:?}");
	}
}

struct Rng(u64);

impl Rng {
	fn next(&mut self) -> u64 {
		self.0 ^= self.0 << 13;
		self.0 ^= self.0 >> 7;
		self.0 ^= self.0 << 17;
		self.0
	}

	fn bytes(&mut self, len: usize) -> Vec<u8> {
		(0..len).map(|_| self.next() as u8).collect()
	}
}

fn outcome(seed: &[u8], path: &str) -> String {
	match derive(seed, path) {
		Ok(secret) => secret.iter().map(|b| format!("{b:02x}")).collect(),
		Err(error) => format!("{error:?}"),
	}
}

/// One line per case: the parse result, the derived secret or error for a valid
/// seed, and the error for a seed of invalid length.
fn corpus() -> Vec<String> {
	let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
	let seed = rng.bytes(64);
	let short_seed = [7u8; 5];
	let mut lines = Vec::new();

	for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 48, 63, 64, 65, 128, 4096] {
		let seed = rng.bytes(len);
		for path in ["m", "m/0'", "m/44'/189189'/0'/0'/0'", "bad", "m/1"] {
			lines.push(format!("seed {len} {path} {}", outcome(&seed, path)));
		}
	}

	let roots = ["m", "M", "", " m", "m ", "/m", "n", "m'"];
	let levels = [
		"0'",
		"1'",
		"44'",
		"044'",
		"00'",
		"+1'",
		"1",
		"0",
		"",
		"'",
		"''",
		"0''",
		" 1'",
		"1 '",
		"2147483647'",
		"2147483648'",
		"4294967295'",
		"4294967296'",
		"99999999999999999999'",
		"1_0'",
		"\u{ff11}'",
		"-1'",
		"0x1'",
		"1h",
		"1H",
		"m",
		"189189'",
		"1'\u{2019}",
		"1\u{2019}",
	];
	let mut paths = Vec::new();
	for root in roots {
		paths.push(root.to_string());
		for first in levels {
			paths.push(format!("{root}/{first}"));
			for second in levels {
				paths.push(format!("{root}/{first}/{second}"));
			}
		}
	}
	for depth in 13..=19 {
		paths.push(format!("m{}", "/0'".repeat(depth)));
		paths.push(format!("m{}/1", "/7'".repeat(depth)));
	}
	for len in 250..=260 {
		paths.push(format!("m/1'{}", "1".repeat(len - 4)));
		paths.push(format!("m/1'{}'", "1".repeat(len - 5)));
	}
	for path in &paths {
		let parsed = match DerivationPath::from_str(path) {
			Ok(_) => "ok".to_string(),
			Err(error) => format!("{error:?}"),
		};
		lines.push(format!(
			"path {path:?} {parsed} {} {}",
			outcome(&seed, path),
			outcome(&short_seed, path)
		));
	}

	for level in levels {
		let stepped = match ChildNumber::from_str(level) {
			Ok(child) => {
				let mut key = ExtendedPrivKey::zeroed();
				ExtendedPrivKey::derive(&seed, "m/3'", &mut key).unwrap();
				key.child_in_place(child);
				key.secret().as_bytes().iter().map(|b| format!("{b:02x}")).collect()
			},
			Err(error) => format!("{error:?}"),
		};
		lines.push(format!("child {level:?} {stepped}"));
	}

	for _ in 0..400 {
		let seed_len = 16 + (rng.next() % 49) as usize;
		let seed = rng.bytes(seed_len);
		let mut path = String::from("m");
		for _ in 0..rng.next() % 17 {
			let index = match rng.next() % 4 {
				0 => rng.next() % 10,
				1 => rng.next() % 100_000,
				2 => (1 << 31) - 1 - rng.next() % 3,
				_ => rng.next() % (1 << 31),
			};
			path.push_str(&format!("/{index}'"));
		}
		lines.push(format!("random {path} {}", outcome(&seed, &path)));
	}
	lines
}

/// Generated cases (every pairing of path roots and level spellings, the
/// depth and length limits, seed lengths, random valid paths) hashed and
/// compared with the digest recorded from 4.1.1. On a mismatch, print the
/// lines with `cargo test --test hderive_compat -- --nocapture` on both
/// versions and diff them.
#[test]
fn generated_corpus_matches_recorded_digest() {
	let lines = corpus();
	let mut hasher = Sha512::new();
	for line in &lines {
		println!("{line}");
		hasher.update(line.as_bytes());
		hasher.update(b"\n");
	}
	let digest: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
	assert_eq!((lines.len(), digest.as_str()), CORPUS);
}

const CORPUS: (usize, &str) = (
	7503,
	"c8a1edcf3ac3bee045c9e9cac14ba3d0f3fe9f742c8ed9112a232db73629b902\
	 346c95bf1dc88b8704e0390ad0c72b68152c63bbe2ad1b43a57a61f710f67a9e",
);
