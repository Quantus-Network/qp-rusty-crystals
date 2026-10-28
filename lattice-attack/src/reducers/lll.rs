//! Floating-point LLL (Schnorr–Euchner style) on a [`Workspace`], and the
//! [`Lll`] reducer that wraps it.

use crate::{
	basis::Basis,
	harness::{Reducer, Step, StepContext},
	reducers::workspace::Workspace,
};

pub const DEFAULT_DELTA: f64 = 0.99;
pub const DEFAULT_ETA: f64 = 0.51;

/// LLL-reduce rows `start..end`, assuming rows `0..start` are already valid in
/// the workspace (they may still be swapped into if the Lovász condition at
/// the boundary fails). `stop` is polled periodically; returns `false` if it
/// fired before the reduction finished. The rows are a valid basis of the
/// same lattice at every return.
pub fn lll(
	ws: &mut Workspace,
	start: usize,
	end: usize,
	delta: f64,
	eta: f64,
	stop: &mut dyn FnMut() -> bool,
) -> bool {
	let mut k = start.max(1);
	ws.ensure(k);
	let mut iter = 0u64;
	while k < end {
		iter += 1;
		if iter.is_multiple_of(64) && stop() {
			return false;
		}
		ws.size_reduce_row(k, eta);
		let m = ws.mu[k][k - 1];
		if ws.r[k] < (delta - m * m) * ws.r[k - 1] {
			ws.swap(k);
			k = (k - 1).max(1);
		} else {
			k += 1;
		}
	}
	true
}

/// Plain LLL as a [`Reducer`]: one step runs LLL to completion (or to the
/// deadline) and returns `Done` once the basis is LLL-reduced.
#[derive(Clone, Debug)]
pub struct Lll {
	pub delta: f64,
	pub eta: f64,
}

impl Default for Lll {
	fn default() -> Self {
		Lll { delta: DEFAULT_DELTA, eta: DEFAULT_ETA }
	}
}

impl Reducer for Lll {
	fn name(&self) -> String {
		format!("lll(delta={}, eta={})", self.delta, self.eta)
	}

	fn step(&mut self, basis: &mut Basis, ctx: &StepContext) -> Step {
		let d = basis.len();
		let mut ws = Workspace::new(std::mem::take(&mut basis.rows));
		let finished = lll(&mut ws, 0, d, self.delta, self.eta, &mut || ctx.should_stop());
		basis.rows = ws.into_rows();
		if finished {
			Step::Done
		} else {
			Step::Continue
		}
	}
}

#[cfg(test)]
mod tests {
	use std::time::Duration;

	use super::*;
	use crate::{
		harness::{run, Budget, NullObserver, Termination},
		instance::{Instance, Variant},
		verify::verify,
	};

	#[test]
	fn textbook_example() {
		// Wikipedia's LLL example: the reduced basis has first vector (0, 1, 0).
		let rows = vec![vec![1, 1, 1], vec![-1, 0, 2], vec![3, 5, 6]];
		let mut ws = Workspace::new(rows);
		assert!(lll(&mut ws, 0, 3, 0.75, 0.5, &mut || false));
		assert!(ws.is_lll_reduced(0.75, 0.5));
		let rows = ws.into_rows();
		assert_eq!(rows[0].iter().map(|x| x * x).sum::<i64>(), 1);
		assert_eq!(rows[1].iter().map(|x| x * x).sum::<i64>(), 2);
	}

	#[test]
	fn reduces_an_instance_and_passes_verification() {
		let inst = Instance::generate(Variant::MlDsa44, [3u8; 32], 20, 20).unwrap();
		let mut basis = inst.start_basis();
		let mut ws = Workspace::new(std::mem::take(&mut basis.rows));
		assert!(lll(&mut ws, 0, inst.dim(), DEFAULT_DELTA, DEFAULT_ETA, &mut || false));
		assert!(ws.is_lll_reduced(DEFAULT_DELTA, DEFAULT_ETA));
		basis.rows = ws.into_rows();
		let score = verify(&inst, &basis).unwrap();
		assert!(score.score_bits > 100.0, "{}", score.score_bits);
		assert!(score.first_norm < 8380417.0);
	}

	#[test]
	fn as_a_reducer_it_finishes_with_done() {
		let inst = Instance::generate(Variant::MlDsa65, [4u8; 32], 15, 15).unwrap();
		let report =
			run(&inst, Lll::default(), &Budget::new(Duration::from_secs(30)), &mut NullObserver);
		assert_eq!(report.termination, Termination::Done);
		assert_eq!(report.counted_steps, 1);
		assert!(report.score_bits().unwrap() > 0.0);
	}

	#[test]
	fn stop_leaves_a_valid_basis() {
		let inst = Instance::generate(Variant::MlDsa44, [5u8; 32], 30, 30).unwrap();
		let mut basis = inst.start_basis();
		let mut ws = Workspace::new(std::mem::take(&mut basis.rows));
		let mut calls = 0;
		let finished = lll(&mut ws, 0, inst.dim(), DEFAULT_DELTA, DEFAULT_ETA, &mut || {
			calls += 1;
			calls >= 3
		});
		assert!(!finished);
		basis.rows = ws.into_rows();
		assert!(verify(&inst, &basis).is_ok());
	}
}
