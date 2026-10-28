//! Reference BKZ: Schnorr–Euchner enumeration as the SVP oracle, unimodular
//! insertion of the vector found, LLL to clean up, and a progressive
//! block-size schedule wrapped as a [`Reducer`].

use std::cmp::min;

use crate::{
	basis::Basis,
	harness::{Reducer, Step, StepContext},
	reducers::{
		lll::{lll, DEFAULT_DELTA, DEFAULT_ETA},
		workspace::Workspace,
	},
};

/// Enumeration radius is capped at this multiple of the block's Gaussian
/// heuristic (BKZ 2.0 convention), which bounds the work on blocks whose
/// first vector is already short.
pub const DEFAULT_GH_FACTOR: f64 = 1.1;

/// The Gaussian heuristic is only accurate enough to use as a radius cap
/// from this block size up; smaller blocks enumerate up to `‖b*_k‖`.
pub const GH_CAP_MIN_BLOCK: usize = 30;

/// Enumeration polls `stop` every this many nodes.
const STOP_POLL_MASK: u64 = (1 << 16) - 1;

/// Shortest nonzero vector of the projected block `[k, k + n)` with squared
/// projected norm strictly below `radius_sq`, as coefficients over the block
/// rows. Returns `None` if no such vector exists or if `stop` fired before
/// one was found. If `stop` fires after a candidate was found, the best
/// candidate so far is returned.
///
/// The workspace must be valid up to `k + n`.
pub fn enumerate(
	ws: &Workspace,
	k: usize,
	n: usize,
	radius_sq: f64,
	stop: &mut dyn FnMut() -> bool,
) -> Option<(Vec<i64>, f64)> {
	let r = &ws.r[k..k + n];
	let mu = |j: usize, i: usize| ws.mu[k + j][k + i];

	let mut x = vec![0i64; n];
	x[0] = 1;
	let mut c = vec![0f64; n];
	let mut w = vec![0i64; n];
	let mut rho = vec![0f64; n + 1];
	let mut last_nonzero = 0usize;
	let mut bound = radius_sq;
	let mut best: Option<(Vec<i64>, f64)> = None;
	let mut i = 0usize;
	let mut nodes = 0u64;

	loop {
		nodes += 1;
		if nodes & STOP_POLL_MASK == 0 && stop() {
			return best;
		}
		let diff = x[i] as f64 - c[i];
		let partial = rho[i + 1] + diff * diff * r[i];
		if partial < bound {
			rho[i] = partial;
			if i > 0 {
				i -= 1;
				c[i] = -(i + 1..n).map(|j| x[j] as f64 * mu(j, i)).sum::<f64>();
				x[i] = c[i].round() as i64;
				w[i] = 1;
				continue;
			}
			best = Some((x.clone(), partial));
			bound = partial;
		}
		i += 1;
		if i == n {
			return best;
		}
		if i >= last_nonzero {
			last_nonzero = i;
			x[i] += 1;
		} else {
			if x[i] as f64 > c[i] {
				x[i] -= w[i];
			} else {
				x[i] += w[i];
			}
			w[i] += 1;
		}
	}
}

/// Replace the block rows `k..k + x.len()` by a basis of the same block
/// lattice whose first row is `Σ x_i b_{k+i}` (up to sign), using only
/// elementary unimodular row operations (Euclid on the coefficients).
pub fn insert(ws: &mut Workspace, k: usize, x: &[i64]) {
	let n = x.len();
	let mut coef = x.to_vec();
	loop {
		let nz: Vec<usize> = (0..n).filter(|&i| coef[i] != 0).collect();
		let &j = nz.iter().min_by_key(|&&i| coef[i].unsigned_abs()).expect("nonzero x");
		if nz.len() == 1 {
			ws.rotate_up(k + j, k);
			return;
		}
		for &i in &nz {
			if i == j {
				continue;
			}
			let q = coef[i] / coef[j];
			if q != 0 {
				coef[i] -= q * coef[j];
				ws.add_multiple(k + j, k + i, q);
			}
		}
	}
}

/// Squared enumeration radius for block `[k, k + n)`.
fn block_radius_sq(ws: &Workspace, k: usize, n: usize, gh_factor: f64) -> f64 {
	let first = ws.r[k] * (1.0 - 1e-6);
	if n < GH_CAP_MIN_BLOCK {
		return first;
	}
	let log_vol: f64 = ws.r[k..k + n].iter().map(|v| 0.5 * v.ln()).sum();
	let log_gh = 0.5 * (n as f64 / (2.0 * core::f64::consts::PI * core::f64::consts::E)).ln() +
		log_vol / n as f64;
	first.min((gh_factor * log_gh.exp()).powi(2))
}

/// One BKZ tour with block size `beta`. Returns the number of insertions, or
/// `None` if `stop` fired (the rows are still a valid basis).
pub fn bkz_tour(
	ws: &mut Workspace,
	beta: usize,
	delta: f64,
	eta: f64,
	gh_factor: f64,
	stop: &mut dyn FnMut() -> bool,
) -> Option<usize> {
	let d = ws.dim();
	let mut insertions = 0;
	for k in 0..d - 1 {
		let n = min(beta, d - k);
		if !lll(ws, k, k + n, delta, eta, stop) {
			return None;
		}
		if stop() {
			return None;
		}
		let radius = block_radius_sq(ws, k, n, gh_factor);
		if let Some((x, _)) = enumerate(ws, k, n, radius, stop) {
			insert(ws, k, &x);
			insertions += 1;
			if !lll(ws, k, k + n, delta, eta, stop) {
				return None;
			}
		}
	}
	Some(insertions)
}

/// LLL first, then BKZ tours whose block size grows by `beta_step` each
/// time a tour makes no insertion, up to `beta_max`. One step is one tour.
#[derive(Clone, Debug)]
pub struct ProgressiveBkz {
	pub beta_start: usize,
	pub beta_max: usize,
	pub beta_step: usize,
	pub delta: f64,
	pub eta: f64,
	pub gh_factor: f64,
	lll_done: bool,
	beta: Option<usize>,
}

impl ProgressiveBkz {
	pub fn new(beta_start: usize, beta_max: usize) -> Self {
		ProgressiveBkz {
			beta_start: beta_start.max(2),
			beta_max: beta_max.max(beta_start),
			beta_step: 2,
			delta: DEFAULT_DELTA,
			eta: DEFAULT_ETA,
			gh_factor: DEFAULT_GH_FACTOR,
			lll_done: false,
			beta: None,
		}
	}

	/// Block size the next tour will use.
	pub fn current_beta(&self) -> usize {
		self.beta.unwrap_or(self.beta_start)
	}
}

impl Default for ProgressiveBkz {
	fn default() -> Self {
		ProgressiveBkz::new(10, 40)
	}
}

impl Reducer for ProgressiveBkz {
	fn name(&self) -> String {
		format!(
			"progressive-bkz(beta={}..{} step {}, delta={}, gh={})",
			self.beta_start, self.beta_max, self.beta_step, self.delta, self.gh_factor
		)
	}

	fn step(&mut self, basis: &mut Basis, ctx: &StepContext) -> Step {
		let d = basis.len();
		let mut ws = Workspace::new(std::mem::take(&mut basis.rows));
		let mut stop = || ctx.should_stop();
		let outcome = if !self.lll_done {
			self.lll_done = lll(&mut ws, 0, d, self.delta, self.eta, &mut stop);
			Step::Continue
		} else {
			let beta_cap = min(self.beta_max, d);
			let beta = min(self.current_beta(), beta_cap);
			self.beta = Some(beta);
			match bkz_tour(&mut ws, beta, self.delta, self.eta, self.gh_factor, &mut stop) {
				Some(0) if beta >= beta_cap => Step::Done,
				Some(0) => {
					self.beta = Some(min(beta + self.beta_step, beta_cap));
					Step::Continue
				},
				_ => Step::Continue,
			}
		};
		basis.rows = ws.into_rows();
		outcome
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

	/// Deterministic small-integer basis.
	fn random_basis(dim: usize, seed: u64) -> Vec<Vec<i64>> {
		let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
		let mut next = || {
			s ^= s << 13;
			s ^= s >> 7;
			s ^= s << 17;
			(s % 21) as i64 - 10
		};
		loop {
			let rows: Vec<Vec<i64>> =
				(0..dim).map(|_| (0..dim).map(|_| next()).collect()).collect();
			let mut ws = Workspace::new(rows.clone());
			ws.ensure(dim);
			if ws.r.iter().all(|&r| r > 0.5) {
				return rows;
			}
		}
	}

	fn brute_force_shortest_sq(rows: &[Vec<i64>], box_radius: i64) -> i128 {
		let n = rows.len();
		let d = rows[0].len();
		let mut best = i128::MAX;
		let mut x = vec![-box_radius; n];
		loop {
			if x.iter().any(|&c| c != 0) {
				let mut v = vec![0i128; d];
				for (c, row) in x.iter().zip(rows) {
					for (vi, &ri) in v.iter_mut().zip(row) {
						*vi += *c as i128 * ri as i128;
					}
				}
				best = best.min(v.iter().map(|a| a * a).sum());
			}
			let mut i = 0;
			loop {
				if i == n {
					return best;
				}
				x[i] += 1;
				if x[i] <= box_radius {
					break;
				}
				x[i] = -box_radius;
				i += 1;
			}
		}
	}

	#[test]
	fn enumeration_matches_brute_force() {
		for seed in 1..6u64 {
			let dim = 5;
			let mut ws = Workspace::new(random_basis(dim, seed));
			assert!(lll(&mut ws, 0, dim, 0.99, 0.51, &mut || false));
			ws.ensure(dim);
			let brute = brute_force_shortest_sq(&ws.rows, 3);
			let found = enumerate(&ws, 0, dim, ws.r[0] * 4.0 + 1.0, &mut || false)
				.map(|(x, _)| {
					let mut v = vec![0i128; dim];
					for (c, row) in x.iter().zip(&ws.rows) {
						for (vi, &ri) in v.iter_mut().zip(row) {
							*vi += *c as i128 * ri as i128;
						}
					}
					v.iter().map(|a| a * a).sum::<i128>()
				})
				.unwrap_or_else(|| ws.rows[0].iter().map(|&a| (a as i128) * (a as i128)).sum());
			assert_eq!(found, brute, "seed {seed}");
		}
	}

	#[test]
	fn enumeration_respects_radius() {
		let dim = 6;
		let mut ws = Workspace::new(random_basis(dim, 9));
		ws.ensure(dim);
		assert!(enumerate(&ws, 0, dim, 0.5, &mut || false).is_none());
	}

	#[test]
	fn enumeration_returns_promptly_when_stopped() {
		let inst = Instance::generate(Variant::MlDsa44, [11u8; 32], 26, 26).unwrap();
		let d = inst.dim();
		let mut ws = Workspace::new(inst.start_basis().rows);
		assert!(lll(&mut ws, 0, d, DEFAULT_DELTA, DEFAULT_ETA, &mut || false));
		ws.ensure(d);
		// A radius far above the shortest vector makes full enumeration of a
		// 53-dimensional block infeasible; `stop` must cut it short.
		let t = std::time::Instant::now();
		let polls = std::cell::Cell::new(0u32);
		let out = enumerate(&ws, 0, d, ws.r[0] * 50.0, &mut || {
			polls.set(polls.get() + 1);
			true
		});
		assert_eq!(polls.get(), 1);
		assert!(t.elapsed() < Duration::from_secs(5));
		if let Some((x, norm_sq)) = out {
			assert!(x.iter().any(|&c| c != 0));
			assert!(norm_sq < ws.r[0] * 50.0);
		}
	}

	#[test]
	fn insert_keeps_the_lattice_and_places_the_vector_first() {
		let inst = Instance::generate(Variant::MlDsa44, [6u8; 32], 6, 6).unwrap();
		let mut basis = inst.start_basis();
		let d = inst.dim();
		let mut ws = Workspace::new(std::mem::take(&mut basis.rows));
		let x = [3i64, -2, 0, 5, 7];
		let k = 2;
		let mut v = vec![0i64; d];
		for (c, row) in x.iter().zip(&ws.rows[k..k + x.len()]) {
			for (vi, &ri) in v.iter_mut().zip(row) {
				*vi += c * ri;
			}
		}
		insert(&mut ws, k, &x);
		let neg: Vec<i64> = v.iter().map(|a| -a).collect();
		assert!(ws.rows[k] == v || ws.rows[k] == neg);
		basis.rows = ws.into_rows();
		assert!(verify(&inst, &basis).is_ok());
	}

	#[test]
	fn tours_improve_on_lll_and_pass_verification() {
		let inst = Instance::generate(Variant::MlDsa44, [7u8; 32], 22, 22).unwrap();
		let d = inst.dim();
		let mut basis = inst.start_basis();
		let mut ws = Workspace::new(std::mem::take(&mut basis.rows));
		assert!(lll(&mut ws, 0, d, DEFAULT_DELTA, DEFAULT_ETA, &mut || false));
		let after_lll = Basis::new(ws.rows.clone());
		let lll_score = verify(&inst, &after_lll).unwrap();

		let mut prev = lll_score.potential;
		for beta in [8, 12, 16] {
			let ins =
				bkz_tour(&mut ws, beta, DEFAULT_DELTA, DEFAULT_ETA, DEFAULT_GH_FACTOR, &mut || {
					false
				});
			assert!(ins.is_some());
			let s = verify(&inst, &Basis::new(ws.rows.clone())).unwrap();
			assert!(s.potential <= prev + 1e-6, "beta {beta}: {} > {prev}", s.potential);
			prev = s.potential;
		}
		let final_score = verify(&inst, &Basis::new(ws.rows.clone())).unwrap();
		assert!(final_score.score_bits > lll_score.score_bits);
		assert!(final_score.first_norm <= lll_score.first_norm);
	}

	#[test]
	fn progressive_bkz_runs_to_done_on_a_small_instance() {
		let inst = Instance::generate(Variant::MlDsa65, [8u8; 32], 10, 10).unwrap();
		let report = run(
			&inst,
			ProgressiveBkz::new(4, 12),
			&Budget::new(Duration::from_secs(60)),
			&mut NullObserver,
		);
		assert_eq!(report.termination, Termination::Done);
		assert!(report.result.is_ok(), "{:?}", report.result);
		let trace: Vec<f64> = report.steps.iter().filter_map(|s| s.approx_score_bits).collect();
		assert!(trace.windows(2).all(|w| w[1] >= w[0] - 1e-6), "{trace:?}");
	}

	#[test]
	fn more_steps_never_score_lower() {
		let inst = Instance::generate(Variant::MlDsa44, [9u8; 32], 18, 18).unwrap();
		let mut short = Budget::new(Duration::from_secs(60));
		short.max_steps = Some(2);
		let mut long = Budget::new(Duration::from_secs(60));
		long.max_steps = Some(6);
		let a = run(&inst, ProgressiveBkz::new(6, 20), &short, &mut NullObserver);
		let b = run(&inst, ProgressiveBkz::new(6, 20), &long, &mut NullObserver);
		assert!(b.score_bits().unwrap() >= a.score_bits().unwrap() - 1e-6);
		assert!(a.score_bits().unwrap() > 0.0);
	}

	#[test]
	fn stops_at_the_deadline_with_a_valid_basis() {
		let inst = Instance::generate(Variant::MlDsa44, [10u8; 32], 40, 40).unwrap();
		let mut budget = Budget::new(Duration::from_millis(300));
		budget.trace = false;
		let report = run(&inst, ProgressiveBkz::new(10, 60), &budget, &mut NullObserver);
		assert!(matches!(report.termination, Termination::Deadline | Termination::Overrun));
		assert!(report.result.is_ok(), "{:?}", report.result);
		assert!(report.elapsed_secs < 2.0);
	}
}
