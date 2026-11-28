//! SLH-DSA key-derivation tests.

use alloc::{
	format,
	string::{String, ToString},
};
use hex_literal::hex;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::{
	hderive::{Error, ExtendedPrivKey},
	slh_dsa_shake_128f::{derive_key_from_mnemonic, derive_key_from_seed, Keypair, ADDRESS_INDEX},
	tests_variants::{test_seed, MNEMONIC},
	HDLatticeError,
};

fn path(index: &str) -> String {
	format!("m/44'/189189'/0'/0'/{index}")
}

macro_rules! per_set_tests {
	($($module:ident, $index:literal => $public:literal;)*) => {
		mod pinned_public_key {
			use super::*;
			$(
				#[test]
				fn $module() {
					use crate::$module::{derive_key_from_seed, Keypair};
					let mut keypair = Keypair::zeroed();
					derive_key_from_seed(&test_seed(), &path($index), &mut keypair).unwrap();
					assert_eq!(keypair.public().bytes, hex!($public));
				}
			)*
		}

		mod accepts_only_the_index_of_its_strength {
			use super::*;
			$(
				#[test]
				fn $module() {
					use crate::$module::{derive_key_from_seed, Keypair, ADDRESS_INDEX};
					assert_eq!(ADDRESS_INDEX, $index);
					for index in 0..16 {
						let path = path(&format!("{index}'"));
						let result = derive_key_from_seed(&test_seed(), &path, &mut Keypair::zeroed());
						if format!("{index}'") == ADDRESS_INDEX {
							assert_eq!(result, Ok(()));
						} else {
							assert_eq!(result, Err(HDLatticeError::InvalidSlhDsaPath(path)));
						}
					}
				}
			)*
		}
	};
}

per_set_tests! {
	slh_dsa_sha2_128s, "2'" => "3c6f07ac0eaa0a6daf3d117268af9f886823437854185f1acb837f6e67f6e38f";
	slh_dsa_shake_128s, "2'" => "c2fd91c3ee4cd958f356592dc812bf4eb3109bc10956523e272973c31c2811da";
	slh_dsa_sha2_128f, "2'" => "c5fd08978e0d514d0b2f8952d4be0090942142269d5aec0fb7f6fd38552de9b3";
	slh_dsa_shake_128f, "2'" => "fdfedcdcac0c3b367e4cbf8fe50b42abb704abf142683cedab36ba4fc8c127c0";
	slh_dsa_sha2_192s, "3'" => "7ffd2cbbc13d0ec9faa74e0a652a97020a40580015349b89e0cf334e258844c29124bf2ac0c02945e3f5021402b4d47f";
	slh_dsa_shake_192s, "3'" => "886d06fd4faa56fee6d2d23965c6cc74aa85089150038778c37d56bf153dcaa9db580950d6efe6433d69aad50c9c22c6";
	slh_dsa_sha2_192f, "3'" => "f9d20846dac677d0e4874989e7eda000d6ae1a724bc60dc7a768afb9ea0e6d000eaad563190d19cb130886d03222b331";
	slh_dsa_shake_192f, "3'" => "55e76bd67c5529ddbd64a899fd09c2d6eaa64a9687e4f862ace20f6d297cf9a56b8ed9157991751700d10284d444eaea";
	slh_dsa_sha2_256s, "4'" => "05d516a5a4b5c5d903f8fb51100e31327d8457387643d30475c1eca7fdd7a42069d46f3f82f94913e7af9ab720c2dd2fd6ddfea9f3180172a6bb845c5910d6f9";
	slh_dsa_shake_256s, "4'" => "f69e49a43cd22ef77b4422b199c60c92af8219c164780a711e9640e00fbbe5be50101d1ec3aa10555cdb1b344bc963bd296edd262141c3a145c7ef428a3a8186";
	slh_dsa_sha2_256f, "4'" => "0bf6acbb643f7f98b2935adaf00579fdab1de9f6f4ab012737cf0b671efc5b517fef6cbc2d1cd999eafbc248a2fe185a86d91dae5de351ebba1f32d2c592093b";
	slh_dsa_shake_256f, "4'" => "ae404b53f3f6023b3b2813fa4e2c439f193d6fe8324ee30db3596b1c28b5a68cb1c411b47c75628bcf3795ae82749cda58ed51567c7bc18cd67a233fb6744e79";
}

/// Rebuilds the key from the documented steps with an independent SHAKE256.
#[test]
fn key_matches_the_documented_construction() {
	use qp_rusty_crystals_sphincs::slh_dsa_shake_128f::{ALGORITHM, SEEDBYTES};

	let path = path(ADDRESS_INDEX);
	let mut xpriv = ExtendedPrivKey::zeroed();
	ExtendedPrivKey::derive(test_seed().as_bytes(), &path, &mut xpriv).unwrap();
	let mut shake = sha3::Shake256::default();
	shake.update(b"qp-rusty-crystals-hdwallet/slh-dsa-seed/");
	shake.update(ALGORITHM.as_bytes());
	shake.update(xpriv.secret().as_bytes());
	let mut seed = [0u8; SEEDBYTES];
	shake.finalize_xof().read(&mut seed);
	let expected = Keypair::generate(&mut seed);

	let mut derived = Keypair::zeroed();
	derive_key_from_seed(&test_seed(), &path, &mut derived).unwrap();
	assert_eq!(derived.secret().to_bytes(), expected.secret().to_bytes());
	assert_eq!(derived.public(), expected.public());
}

#[test]
fn rejects_malformed_paths() {
	let paths = [
		"m/44'/189189189'/0'/0'/2'",
		"m/44'/189189'/2'/0'/0'",
		"m/44'/189189'/0'/2'",
		"m/44'/189189'/0'/0'/2'/0'",
		"m/44'/189189'/0'/0'/0'/2'",
	];
	for path in paths {
		let error = Err(HDLatticeError::InvalidSlhDsaPath(path.to_string()));
		let mut keypair = Keypair::zeroed();
		assert_eq!(derive_key_from_seed(&test_seed(), path, &mut keypair), error);
		assert_eq!(derive_key_from_mnemonic(MNEMONIC, None, path, &mut keypair), error);
		assert_eq!(derive_key_from_mnemonic("not a mnemonic", None, path, &mut keypair), error);
		assert_eq!(keypair.public().bytes, [0u8; 32]);
	}
}

#[test]
fn does_not_check_the_purpose() {
	let mut keypair = Keypair::zeroed();
	assert_eq!(derive_key_from_seed(&test_seed(), "m/0'/189189'/0'/0'/2'", &mut keypair), Ok(()));
}

#[test]
fn keeps_generic_path_errors() {
	let mut keypair = Keypair::zeroed();
	assert_eq!(
		derive_key_from_seed(&test_seed(), "m/44'/189189'/0'/0'/2", &mut keypair),
		Err(HDLatticeError::GenericError(Error::NotHardened))
	);
}

#[test]
fn parameter_sets_sharing_a_path_get_independent_keys() {
	let path = path(ADDRESS_INDEX);
	let mut shake = Keypair::zeroed();
	derive_key_from_seed(&test_seed(), &path, &mut shake).unwrap();
	let mut sha2 = crate::slh_dsa_sha2_128f::Keypair::zeroed();
	crate::slh_dsa_sha2_128f::derive_key_from_seed(&test_seed(), &path, &mut sha2).unwrap();
	let mut small = crate::slh_dsa_shake_128s::Keypair::zeroed();
	crate::slh_dsa_shake_128s::derive_key_from_seed(&test_seed(), &path, &mut small).unwrap();

	let secrets = [shake.secret().to_bytes(), sha2.secret().to_bytes(), small.secret().to_bytes()];
	for (i, a) in secrets.iter().enumerate() {
		for b in &secrets[i + 1..] {
			for part in 0..3 {
				assert_ne!(a[16 * part..16 * (part + 1)], b[16 * part..16 * (part + 1)]);
			}
		}
	}
}
