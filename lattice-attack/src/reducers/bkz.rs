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

/// Insert `v = Σ x_i b_{k+i}` at position `k` and LLL-reduce the now
/// dependent block `k..k + n + 1` until one row becomes zero and is dropped.
/// This disturbs the rest of the block far less than [`insert_euclid`], so
/// later tours have less to redo. Returns `false` (with the rows restored to
/// their state on entry) if no zero row appeared within an iteration cap,
/// which floating-point Gram–Schmidt data can occasionally cause.
pub fn insert_lll(
	ws: &mut Workspace,
	k: usize,
	x: &[i64],
	delta: f64,
	eta: f64,
	stop: &mut dyn FnMut() -> bool,
) -> bool {
	let n = x.len();
	// Swaps may reach below `k`, so everything up to the block end is backed up.
	let backup: Vec<Vec<i64>> = ws.rows[..k + n].to_vec();
	let width = ws.rows[0].len();
	let mut v = vec![0i64; width];
	for (c, row) in x.iter().zip(&ws.rows[k..k + n]) {
		for (vi, &ri) in v.iter_mut().zip(row) {
			*vi = vi.checked_add(c.checked_mul(ri).expect("overflow")).expect("overflow");
		}
	}
	ws.insert_row(k, v);

	let end = k + n + 1;
	let cap = 64 * (n + 1) * (n + 1);
	let mut kk = k.max(1);
	ws.ensure(kk);
	let mut iters = 0usize;
	let mut removed = false;
	while kk < end {
		iters += 1;
		if iters > cap || (iters.is_multiple_of(64) && stop()) {
			break;
		}
		ws.size_reduce_row(kk, eta);
		if ws.row_is_zero(kk) {
			ws.remove_row(kk);
			removed = true;
			break;
		}
		let m = ws.mu[kk][kk - 1];
		if ws.r[kk] < (delta - m * m) * ws.r[kk - 1] {
			ws.swap(kk);
			kk = (kk - 1).max(1);
		} else {
			kk += 1;
		}
	}
	if !removed {
		ws.remove_row(k);
		for (i, row) in backup.into_iter().enumerate() {
			ws.rows[i] = row;
		}
		ws.invalidate_from(0);
		return false;
	}
	true
}

/// Replace the block rows `k..k + x.len()` by a basis of the same block
/// lattice whose first row is `Σ x_i b_{k+i}` (up to sign), using only
/// elementary unimodular row operations (Euclid on the coefficients).
/// Always succeeds; used as the fallback for [`insert_lll`].
pub fn insert_euclid(ws: &mut Workspace, k: usize, x: &[i64]) {
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
			if !insert_lll(ws, k, &x, delta, eta, stop) {
				insert_euclid(ws, k, &x);
			}
			insertions += 1;
			if !lll(ws, k, k + n, delta, eta, stop) {
				return None;
			}
		}
	}
	Some(insertions)
}

/// Log-potential of the workspace rows in bits, from its `f64` data.
fn potential_bits(ws: &mut Workspace) -> f64 {
	let d = ws.dim();
	ws.ensure(d);
	ws.r.iter()
		.enumerate()
		.map(|(i, r)| (d - 1 - i) as f64 * 0.5 * r.ln())
		.sum::<f64>() /
		core::f64::consts::LN_2
}

/// LLL first, then BKZ tours with a growing block size. One step is one
/// tour. The block size advances by `beta_step` after `tours_per_beta` tours,
/// or earlier if a tour stalls (no insertion, or a potential gain below
/// `stall_bits_per_dim · d` bits). At `beta_max`, tours continue until one
/// stalls, then the reducer reports `Done`.
#[derive(Clone, Debug)]
pub struct ProgressiveBkz {
	pub beta_start: usize,
	pub beta_max: usize,
	pub beta_step: usize,
	/// Tours to run at each block size below `beta_max` before advancing.
	/// Small block sizes stay productive for many tours, but under a time
	/// budget it pays to move on quickly.
	pub tours_per_beta: usize,
	pub delta: f64,
	pub eta: f64,
	pub gh_factor: f64,
	/// A tour that improves the potential by less than this many bits per
	/// dimension counts as stalled. Without it, floating-point noise can
	/// keep producing one or two insertions per tour indefinitely.
	pub stall_bits_per_dim: f64,
	lll_done: bool,
	beta: Option<usize>,
	tours_at_beta: usize,
}

impl ProgressiveBkz {
	pub fn new(beta_start: usize, beta_max: usize) -> Self {
		ProgressiveBkz {
			beta_start: beta_start.max(2),
			beta_max: beta_max.max(beta_start),
			beta_step: 2,
			tours_per_beta: 2,
			delta: DEFAULT_DELTA,
			eta: DEFAULT_ETA,
			gh_factor: DEFAULT_GH_FACTOR,
			stall_bits_per_dim: 0.05,
			lll_done: false,
			beta: None,
			tours_at_beta: 0,
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
			"progressive-bkz(beta={}..{} step {} x{} tours, delta={}, gh={})",
			self.beta_start,
			self.beta_max,
			self.beta_step,
			self.tours_per_beta,
			self.delta,
			self.gh_factor
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
			let before = potential_bits(&mut ws);
			match bkz_tour(&mut ws, beta, self.delta, self.eta, self.gh_factor, &mut stop) {
				Some(insertions) => {
					self.tours_at_beta += 1;
					let gained = before - potential_bits(&mut ws);
					let stalled = insertions == 0 || gained < self.stall_bits_per_dim * d as f64;
					if stalled && beta >= beta_cap {
						Step::Done
					} else {
						if beta < beta_cap && (stalled || self.tours_at_beta >= self.tours_per_beta)
						{
							self.beta = Some(min(beta + self.beta_step, beta_cap));
							self.tours_at_beta = 0;
						}
						Step::Continue
					}
				},
				None => Step::Continue,
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
		insert_euclid(&mut ws, k, &x);
		let neg: Vec<i64> = v.iter().map(|a| -a).collect();
		assert!(ws.rows[k] == v || ws.rows[k] == neg);
		basis.rows = ws.into_rows();
		assert!(verify(&inst, &basis).is_ok());
	}

	#[test]
	fn insert_lll_keeps_the_lattice_and_shortens_the_block_front() {
		let inst = Instance::generate(Variant::MlDsa44, [12u8; 32], 16, 16).unwrap();
		let d = inst.dim();
		let mut ws = Workspace::new(inst.start_basis().rows);
		assert!(lll(&mut ws, 0, d, DEFAULT_DELTA, DEFAULT_ETA, &mut || false));
		let (k, n) = (3, 12);
		let before = potential_bits(&mut ws);
		let old_rk = ws.r[k];
		let (x, norm_sq) =
			enumerate(&ws, k, n, ws.r[k] * (1.0 - 1e-6), &mut || false).expect("improvement");
		assert!(norm_sq < old_rk);
		assert!(insert_lll(&mut ws, k, &x, DEFAULT_DELTA, DEFAULT_ETA, &mut || false));
		assert_eq!(ws.dim(), d);
		ws.invalidate_from(0);
		// The inserted vector may travel below `k` if it is shorter there too;
		// either way the block front is no longer than before and the
		// potential dropped.
		assert!(ws.r[k] <= old_rk * (1.0 + 1e-9), "{} vs {}", ws.r[k], old_rk);
		assert!(potential_bits(&mut ws) < before);
		assert!(verify(&inst, &Basis::new(ws.into_rows())).is_ok());
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
		// Cooperative stopping lands inside the window, so no step is discarded.
		assert_eq!(report.termination, Termination::Deadline, "{:?}", report.steps);
		assert!(report.result.is_ok(), "{:?}", report.result);
		assert!(report.elapsed_secs < 2.0);
	}
}
