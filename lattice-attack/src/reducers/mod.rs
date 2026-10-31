//! Reference reducers. These are baselines demonstrating the [`Reducer`]
//! contract, not competitive implementations.
//!
//! [`Reducer`]: crate::harness::Reducer

pub mod bkz;
pub mod lll;
pub mod workspace;

pub use bkz::ProgressiveBkz;
pub use lll::Lll;
