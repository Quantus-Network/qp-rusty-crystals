//! SLH-DSA, the stateless hash-based signature scheme standardized from
//! SPHINCS+ in FIPS 205.
//!
//! Each of the twelve parameter sets has a module with the same API:
//!
//! ```
//! use qp_rusty_crystals_sphincs::slh_dsa_shake_128f::{Keypair, SEEDBYTES};
//!
//! let mut seed = [7u8; SEEDBYTES]; // use a cryptographic random source
//! let keypair = Keypair::generate(&mut seed);
//! let signature = keypair.sign(b"message", None, None).unwrap();
//! assert!(keypair.verify(b"message", &signature[..], None));
//! ```
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(test)]
extern crate std;

mod adrs;
mod errors;
mod frontend;
mod hash;
mod params;
mod sha2;
mod slh;

#[cfg(test)]
mod acvp;

pub use errors::{KeyParsingError, SignatureError};
pub use frontend::PreHash;

macro_rules! parameter_sets {
	($($module:ident => $params:ident, $name:literal;)*) => {
		$(
			#[doc = concat!($name, " (FIPS 205).")]
			pub mod $module {
				crate::frontend::define_slh_dsa!(crate::params::$params);
			}
		)*
	};
}

parameter_sets! {
	slh_dsa_sha2_128s => SHA2_128S, "SLH-DSA-SHA2-128s";
	slh_dsa_shake_128s => SHAKE_128S, "SLH-DSA-SHAKE-128s";
	slh_dsa_sha2_128f => SHA2_128F, "SLH-DSA-SHA2-128f";
	slh_dsa_shake_128f => SHAKE_128F, "SLH-DSA-SHAKE-128f";
	slh_dsa_sha2_192s => SHA2_192S, "SLH-DSA-SHA2-192s";
	slh_dsa_shake_192s => SHAKE_192S, "SLH-DSA-SHAKE-192s";
	slh_dsa_sha2_192f => SHA2_192F, "SLH-DSA-SHA2-192f";
	slh_dsa_shake_192f => SHAKE_192F, "SLH-DSA-SHAKE-192f";
	slh_dsa_sha2_256s => SHA2_256S, "SLH-DSA-SHA2-256s";
	slh_dsa_shake_256s => SHAKE_256S, "SLH-DSA-SHAKE-256s";
	slh_dsa_sha2_256f => SHA2_256F, "SLH-DSA-SHA2-256f";
	slh_dsa_shake_256f => SHAKE_256F, "SLH-DSA-SHAKE-256f";
}
