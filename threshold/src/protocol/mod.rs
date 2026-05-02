//! Internal protocol implementation for threshold ML-DSA-87.
//!
//! This module contains the cryptographic primitives used by the threshold
//! signing protocol. These are internal implementation details and are not
//! part of the public API.

pub(crate) mod primitives;
pub(crate) mod secret_sharing;
pub(crate) mod signing;
