//! Timed lattice-reduction challenge against the ML-DSA key-recovery lattice.
//!
//! See `README.md` for the design. In short:
//!
//! - [`instance`] turns a public seed into a lattice shaped exactly like the one an attacker
//!   reduces to recover an ML-DSA secret key, with no planted secret.
//! - [`basis`] is the plain integer representation exchanged between the harness, reducers and the
//!   verifier.
//! - [`gso`] computes Gram–Schmidt profiles, both a fast `f64` version for progress traces and a
//!   fixed-point `BigInt` version from the exact Gram matrix that the verifier trusts.
//! - [`verify`] decides whether a submitted basis generates the instance's lattice and scores it by
//!   log-potential improvement.
//! - [`harness`] defines the [`Reducer`] trait contestants implement, runs one under a wall-clock
//!   budget, and produces a [`Report`].
//! - [`reducers`] holds the reference implementations (LLL, progressive BKZ).

pub mod basis;
pub mod gso;
pub mod harness;
pub mod instance;
pub mod reducers;
pub mod verify;

pub use basis::Basis;
pub use gso::Profile;
pub use harness::{run, Budget, Observer, Reducer, Report, Step, StepContext, Termination};
pub use instance::{Instance, InstanceError, Variant, Q};
pub use verify::{Rejection, Score};
