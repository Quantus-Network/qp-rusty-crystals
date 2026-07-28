//! Feature-selected ML-DSA frontend types for the active parameter set.
//!
//! Priority matches [`crate::params`]: 87 > 65 > 44 when multiple features
//! are enabled (e.g. workspace `--all-features`).

#[cfg(feature = "ml-dsa-87")]
pub use qp_rusty_crystals_dilithium::ml_dsa_87::{PublicKey as MlDsaPublicKey, MAX_MESSAGE_SIZE};

#[cfg(all(feature = "ml-dsa-65", not(feature = "ml-dsa-87")))]
pub use qp_rusty_crystals_dilithium::ml_dsa_65::{PublicKey as MlDsaPublicKey, MAX_MESSAGE_SIZE};

#[cfg(all(feature = "ml-dsa-44", not(feature = "ml-dsa-87"), not(feature = "ml-dsa-65")))]
pub use qp_rusty_crystals_dilithium::ml_dsa_44::{PublicKey as MlDsaPublicKey, MAX_MESSAGE_SIZE};

#[cfg(all(test, feature = "ml-dsa-87"))]
pub use qp_rusty_crystals_dilithium::ml_dsa_87::{Keypair, SecretKey, SIGNBYTES};

#[cfg(all(test, feature = "ml-dsa-65", not(feature = "ml-dsa-87")))]
pub use qp_rusty_crystals_dilithium::ml_dsa_65::{Keypair, SecretKey, SIGNBYTES};

#[cfg(all(
	test,
	feature = "ml-dsa-44",
	not(feature = "ml-dsa-87"),
	not(feature = "ml-dsa-65")
))]
pub use qp_rusty_crystals_dilithium::ml_dsa_44::{Keypair, SecretKey, SIGNBYTES};
