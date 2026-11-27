//! SLH-DSA key-derivation tests.

use alloc::string::ToString;
use hex_literal::hex;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::{
	hderive::{Error, ExtendedPrivKey},
	slh_dsa_shake_128f::{derive_key_from_mnemonic, derive_key_from_seed, Keypair},
	tests_variants::{test_seed, MNEMONIC, SLH_DSA_PATH},
	HDLatticeError,
};

macro_rules! pinned_public_keys {
	($($module:ident => $public:literal;)*) => {
		mod pinned_public_key {
			use super::*;
			$(
				#[test]
				fn $module() {
					let mut keypair = crate::$module::Keypair::zeroed();
					crate::$module::derive_key_from_seed(&test_seed(), SLH_DSA_PATH, &mut keypair)
						.unwrap();
					assert_eq!(keypair.public().bytes, hex!($public));
				}
			)*
		}
	};
}

pinned_public_keys! {
	slh_dsa_sha2_128s => "3c6f07ac0eaa0a6daf3d117268af9f886823437854185f1acb837f6e67f6e38f";
	slh_dsa_shake_128s => "c2fd91c3ee4cd958f356592dc812bf4eb3109bc10956523e272973c31c2811da";
	slh_dsa_sha2_128f => "c5fd08978e0d514d0b2f8952d4be0090942142269d5aec0fb7f6fd38552de9b3";
	slh_dsa_shake_128f => "fdfedcdcac0c3b367e4cbf8fe50b42abb704abf142683cedab36ba4fc8c127c0";
	slh_dsa_sha2_192s => "f129c5ae3915c9f090c18c3916e815004cef67d1af0b5b6edc1dc4faf3fc9ecfdb2a01eabd28ebbe9c2c7fc4849272c2";
	slh_dsa_shake_192s => "770037e24ebaf2d6bf561a2442a2941f83ce9fef2299115cfae75da811317bdc8533b51f7131abd924f2c95d0ebf691f";
	slh_dsa_sha2_192f => "0375210053e020edca633c556335bad91f0294504f670ae7ecb09dab284f3d0253b12cdadcbbdf4e3878fd4254880008";
	slh_dsa_shake_192f => "77be664f8f3dc128bb86e3eabbb58ded372e27f1c9827caee7a44ff966400286ecce65274a5a209fd0c6e9f5f9f638a6";
	slh_dsa_sha2_256s => "c36cf7fc8a9a23bad19dec5af7f4994301bb1ab8e865b47b6baf28eeaa1af781898cf04bfdadd088d941b114dc3eb2a63f8c94fd6cfe09f2c2cc2ce68f9ca7c4";
	slh_dsa_shake_256s => "d6fffa91b8a9c819ee773176ff63a5aec67a0ebe1d8117e033e159f7eeab06f5b6ebe91a6463ac90d5ea652ffafd5939bf80e687b1a3eb9de944c3ce9f048b11";
	slh_dsa_sha2_256f => "67ab1d5977a04e446632ce6a7e40ef7dca01917fe6449f1d9314d19dfb8b455545df0f47b0c6e5642369a0c0840e7352d3d8d792ee9c2732cc47f884d36cc7ed";
	slh_dsa_shake_256f => "44c66bbce5afa7852d3044ceb4d3e70fbe0b234e91a2caf060a2dd1cc85961616a0aece209bf2a3c1e4cdca8a7b4cc497b98e8f63d5f911a22e3c1ad47ccbb72";
}

/// Rebuilds the key from the documented steps with an independent SHAKE256.
#[test]
fn key_matches_the_documented_construction() {
	use qp_rusty_crystals_sphincs::slh_dsa_shake_128f::{ALGORITHM, SEEDBYTES};

	let mut xpriv = ExtendedPrivKey::zeroed();
	ExtendedPrivKey::derive(test_seed().as_bytes(), SLH_DSA_PATH, &mut xpriv).unwrap();
	let mut shake = sha3::Shake256::default();
	shake.update(b"qp-rusty-crystals-hdwallet/slh-dsa-seed/");
	shake.update(ALGORITHM.as_bytes());
	shake.update(xpriv.secret().as_bytes());
	let mut seed = [0u8; SEEDBYTES];
	shake.finalize_xof().read(&mut seed);
	let expected = Keypair::generate(&mut seed);

	let mut derived = Keypair::zeroed();
	derive_key_from_seed(&test_seed(), SLH_DSA_PATH, &mut derived).unwrap();
	assert_eq!(derived.secret().to_bytes(), expected.secret().to_bytes());
	assert_eq!(derived.public(), expected.public());
}

#[test]
fn rejects_paths_of_other_schemes() {
	let paths = [
		"m/44'/189189'/0'/0'/0'",
		"m/44'/189189'/0'/0'/1'",
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
fn keeps_generic_path_errors() {
	let mut keypair = Keypair::zeroed();
	assert_eq!(
		derive_key_from_seed(&test_seed(), "m/44'/189189'/0'/0'/2", &mut keypair),
		Err(HDLatticeError::GenericError(Error::NotHardened))
	);
}

#[test]
fn parameter_sets_get_independent_keys() {
	let mut shake = Keypair::zeroed();
	derive_key_from_seed(&test_seed(), SLH_DSA_PATH, &mut shake).unwrap();
	let mut sha2 = crate::slh_dsa_sha2_128f::Keypair::zeroed();
	crate::slh_dsa_sha2_128f::derive_key_from_seed(&test_seed(), SLH_DSA_PATH, &mut sha2).unwrap();
	let mut small = crate::slh_dsa_shake_128s::Keypair::zeroed();
	crate::slh_dsa_shake_128s::derive_key_from_seed(&test_seed(), SLH_DSA_PATH, &mut small)
		.unwrap();

	let secrets = [shake.secret().to_bytes(), sha2.secret().to_bytes(), small.secret().to_bytes()];
	for (i, a) in secrets.iter().enumerate() {
		for b in &secrets[i + 1..] {
			for part in 0..3 {
				assert_ne!(a[16 * part..16 * (part + 1)], b[16 * part..16 * (part + 1)]);
			}
		}
	}
}
