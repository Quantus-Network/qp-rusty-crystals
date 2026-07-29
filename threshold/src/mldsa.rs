//! ML-DSA frontend types for the active parameter set.
//!
//! The 87 > 65 > 44 feature-priority selection lives in one place —
//! [`crate::params`]'s `define_active_variant!` — and this module only
//! re-exports from its [`crate::params::active_frontend`] alias.

pub use crate::params::active_frontend::{PublicKey as MlDsaPublicKey, MAX_MESSAGE_SIZE};

#[cfg(test)]
pub use crate::params::active_frontend::{Keypair, SecretKey, SIGNBYTES};
