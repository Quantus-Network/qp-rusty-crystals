//! Timed lattice-reduction challenge against the ML-DSA key-recovery lattice.
//!
//! See `README.md` for the design. In short:
//!
//! - [`instance`] turns a public seed into a lattice shaped exactly like the one an attacker
//!   reduces to recover an ML-DSA secret key, with no planted secret.
//! - [`basis`] is the plain integer representation exchanged between the harness, reducers and the
//!   verifier.

pub mod basis;
pub mod instance;

pub use basis::Basis;
pub use instance::{Instance, InstanceError, Variant, Q};
