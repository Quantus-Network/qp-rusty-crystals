//! Runs a [`Reducer`] against an instance under a wall-clock budget and hands
//! the result to the verifier.
//!
//! The harness owns the clock. The reducer runs on a worker thread; after
//! every step that returns before the deadline it stores a snapshot of the
//! basis, and the newest such snapshot is what gets scored. Whether a step
//! counts is decided by the time it returned, not by when the harness thread
//! got round to looking at it, so slow observers or tracing cannot cost the
//! run any work. If a step is still running `grace` after the deadline, a
//! watchdog ends the run on the last snapshot.

use std::{
	io::{self, Write},
	sync::{
		atomic::{AtomicBool, Ordering},
		mpsc::{self, RecvTimeoutError},
		Arc, Mutex,
	},
	thread,
	time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

use crate::{
	basis::Basis,
	instance::{Instance, InstanceDescriptor},
	verify::{score_fast, verify, Rejection, Score},
};

/// What a reducer reports after a step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Step {
	/// More work is possible; call again if time remains.
	Continue,
	/// The reducer has nothing further to do (e.g. it converged).
	Done,
}

/// Clock information handed to every step.
#[derive(Clone, Debug)]
pub struct StepContext {
	pub started: Instant,
	/// Steps that return after this instant are discarded.
	pub deadline: Instant,
	/// [`Self::should_stop`] turns true this long before `deadline`, so a
	/// reducer that stops when asked still returns inside the window.
	pub soft_margin: Duration,
	/// Zero-based index of this step.
	pub step: u64,
	/// The operator's flag, shared by every run using the same [`Budget`].
	cancel: Arc<AtomicBool>,
	/// Raised by the harness when this run is over.
	stop: Arc<AtomicBool>,
}

impl StepContext {
	/// Time until the hard deadline.
	pub fn remaining(&self) -> Duration {
		self.deadline.saturating_duration_since(Instant::now())
	}

	pub fn elapsed(&self) -> Duration {
		self.started.elapsed()
	}

	/// True once the run was cancelled or the soft deadline
	/// (`deadline − soft_margin`) has passed. Reducers doing long inner loops
	/// should poll this and return promptly.
	pub fn should_stop(&self) -> bool {
		self.cancelled() || self.remaining() <= self.soft_margin
	}

	/// True once the operator cancelled, or the harness has finished this
	/// run (watchdog fired, or a result was already decided).
	pub fn cancelled(&self) -> bool {
		self.cancel.load(Ordering::Relaxed) || self.stop.load(Ordering::Relaxed)
	}

	/// A context for step 0 of a run starting now, for driving reducers
	/// directly in tests.
	#[cfg(test)]
	pub(crate) fn for_tests(budget: &Budget) -> Self {
		let started = Instant::now();
		StepContext {
			started,
			deadline: started + budget.wall,
			soft_margin: budget.soft_margin,
			step: 0,
			cancel: budget.cancel.clone(),
			stop: Arc::new(AtomicBool::new(false)),
		}
	}
}

/// A lattice reduction algorithm. BKZ is one implementation; contestants
/// supply their own.
///
/// `step` mutates `basis` in place. Every call must leave `basis` a basis of
/// the same lattice (the verifier checks, but a step that returns garbage
/// forfeits the run). Steps should be sized so that returning shortly after
/// `ctx.deadline` is possible; a step that returns after the deadline is
/// discarded.
pub trait Reducer: Send {
	fn name(&self) -> String;
	fn step(&mut self, basis: &mut Basis, ctx: &StepContext) -> Step;
}

/// Time budget and harness options.
#[derive(Clone, Debug)]
pub struct Budget {
	/// Wall-clock allowance measured from just before the first step. Capped
	/// at [`MAX_WALL`].
	pub wall: Duration,
	/// How long past the deadline to wait for an in-flight step before the
	/// watchdog gives up on it. Capped at [`MAX_WALL`].
	pub grace: Duration,
	/// How long before the deadline [`StepContext::should_stop`] starts
	/// returning true. Capped at half of `wall`.
	pub soft_margin: Duration,
	pub max_steps: Option<u64>,
	/// Compute an approximate `f64` score after counted steps (costs `O(d³)`
	/// each; fine for small instances, disable for large ones). Tracing runs
	/// on the harness thread and never delays the reducer; when it cannot
	/// keep up, intermediate steps go untraced.
	pub trace: bool,
	/// Minimum spacing between trace computations.
	pub trace_min_interval: Duration,
	/// Attach the final basis to the report so it can be re-verified offline.
	pub include_basis: bool,
	/// Set to `true` from anywhere to stop the run after the current step.
	/// Shared by clones of this budget; the harness itself never writes it.
	pub cancel: Arc<AtomicBool>,
}

/// Longest budget or grace period: ten years, so that adding it to an
/// [`Instant`] cannot overflow.
pub const MAX_WALL: Duration = Duration::from_secs(10 * 365 * 24 * 3600);

impl Budget {
	/// Defaults: 5 s grace, soft margin of 50 ms plus 0.5 % of `wall` (at most
	/// a quarter of it), tracing on, basis included.
	pub fn new(wall: Duration) -> Self {
		let wall = wall.min(MAX_WALL);
		Budget {
			wall,
			grace: Duration::from_secs(5),
			soft_margin: (Duration::from_millis(50) + wall / 200).min(wall / 4),
			max_steps: None,
			trace: true,
			trace_min_interval: Duration::ZERO,
			include_basis: true,
			cancel: Arc::new(AtomicBool::new(false)),
		}
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Termination {
	/// A step returned in time and the budget was exhausted.
	Deadline,
	/// The last step returned after the deadline and was discarded.
	Overrun,
	/// A step was still running `grace` after the deadline.
	Watchdog,
	/// The reducer returned [`Step::Done`].
	Done,
	/// The cancel flag was raised.
	Cancelled,
	MaxSteps,
	/// The reducer panicked; the run is scored on the last counted snapshot.
	ReducerPanicked,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StepEvent {
	pub step: u64,
	/// Seconds since the run started when the step returned.
	pub elapsed_secs: f64,
	pub step_secs: f64,
	/// Whether the step returned before the deadline and was kept.
	pub counted: bool,
	pub outcome: Step,
	/// Approximate score after this step, if tracing was on and the step
	/// counted.
	pub approx_score_bits: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Report {
	pub instance: InstanceDescriptor,
	pub reducer: String,
	pub budget_secs: f64,
	pub grace_secs: f64,
	pub elapsed_secs: f64,
	pub termination: Termination,
	pub steps: Vec<StepEvent>,
	pub counted_steps: u64,
	/// Verifier output on the final counted snapshot.
	pub result: Result<Score, Rejection>,
	pub basis: Option<Basis>,
}

impl Report {
	pub fn score_bits(&self) -> Option<f64> {
		self.result.as_ref().ok().map(|s| s.score_bits)
	}
}

/// Receives progress during a run.
pub trait Observer {
	fn on_start(&mut self, _instance: &InstanceDescriptor, _reducer: &str, _budget: &Budget) {}
	fn on_step(&mut self, _event: &StepEvent) {}
	fn on_finish(&mut self, _report: &Report) {}
}

pub struct NullObserver;

impl Observer for NullObserver {}

/// Human-readable progress on stderr.
pub struct StderrObserver;

impl Observer for StderrObserver {
	fn on_start(&mut self, instance: &InstanceDescriptor, reducer: &str, budget: &Budget) {
		eprintln!(
			"[start] {} {} n={} m={} d={} id={} budget={:.1}s",
			reducer,
			instance.variant,
			instance.n,
			instance.m,
			instance.dim,
			&instance.id[..16],
			budget.wall.as_secs_f64()
		);
	}

	fn on_step(&mut self, e: &StepEvent) {
		let score = e.approx_score_bits.map(|s| format!(" score≈{s:.1}")).unwrap_or_default();
		let flag = if e.counted { "" } else { " (discarded)" };
		eprintln!(
			"[step {}] t={:.2}s dt={:.2}s{}{}",
			e.step, e.elapsed_secs, e.step_secs, score, flag
		);
	}

	fn on_finish(&mut self, r: &Report) {
		match &r.result {
			Ok(s) => eprintln!(
				"[finish] {:?} after {:.2}s, {} steps: score {:.2} bits, |b1|={:.1} ({:.2}×GH), slope {:.4}",
				r.termination,
				r.elapsed_secs,
				r.counted_steps,
				s.score_bits,
				s.first_norm,
				s.first_over_gh,
				s.slope
			),
			Err(e) => eprintln!(
				"[finish] {:?} after {:.2}s, {} steps: REJECTED: {e}",
				r.termination, r.elapsed_secs, r.counted_steps
			),
		}
	}
}

/// One JSON object per line: `start`, `step`, and `finish` events. Each line
/// is serialised in memory and written whole, so a failed write never leaves
/// a partial record; after the first failure nothing more is written and the
/// error is returned by [`Self::finish`].
pub struct JsonlObserver<W: Write> {
	out: W,
	error: Option<io::Error>,
}

impl<W: Write> JsonlObserver<W> {
	pub fn new(out: W) -> Self {
		JsonlObserver { out, error: None }
	}

	fn emit<T: Serialize>(&mut self, event: &str, payload: &T) {
		#[derive(Serialize)]
		struct Line<'a, T> {
			event: &'a str,
			#[serde(flatten)]
			payload: &'a T,
		}
		if self.error.is_some() {
			return;
		}
		let result = serde_json::to_vec(&Line { event, payload })
			.map_err(io::Error::from)
			.and_then(|mut line| {
				line.push(b'\n');
				self.out.write_all(&line)
			});
		if let Err(e) = result {
			self.error = Some(e);
		}
	}

	/// The first write error, if any.
	pub fn error(&self) -> Option<&io::Error> {
		self.error.as_ref()
	}

	/// Flush and return the writer, or the first error that occurred.
	pub fn finish(mut self) -> io::Result<W> {
		match self.error.take() {
			Some(e) => Err(e),
			None => {
				self.out.flush()?;
				Ok(self.out)
			},
		}
	}
}

impl<W: Write> Observer for JsonlObserver<W> {
	fn on_start(&mut self, instance: &InstanceDescriptor, reducer: &str, budget: &Budget) {
		#[derive(Serialize)]
		struct Start<'a> {
			instance: &'a InstanceDescriptor,
			reducer: &'a str,
			budget_secs: f64,
		}
		self.emit("start", &Start { instance, reducer, budget_secs: budget.wall.as_secs_f64() });
	}

	fn on_step(&mut self, event: &StepEvent) {
		self.emit("step", event);
	}

	fn on_finish(&mut self, report: &Report) {
		self.emit("finish", report);
	}
}

enum Msg {
	Step {
		step: u64,
		started_at: Instant,
		finished_at: Instant,
		outcome: Step,
	},
	/// The worker saw the deadline or cancel flag before starting a step.
	Idle {
		at: Instant,
	},
}

/// The newest basis from a step that returned before the deadline.
struct Snapshot {
	step: u64,
	basis: Arc<Basis>,
}

/// Run `reducer` on `instance` under `budget` and verify the result.
pub fn run<R: Reducer + 'static>(
	instance: &Instance,
	mut reducer: R,
	budget: &Budget,
	observer: &mut dyn Observer,
) -> Report {
	let name = reducer.name();
	observer.on_start(&instance.descriptor(), &name, budget);

	let start_basis = instance.start_basis();
	let cancel = budget.cancel.clone();
	let stop = Arc::new(AtomicBool::new(false));
	let wall = budget.wall.min(MAX_WALL);
	let grace = budget.grace.min(MAX_WALL);
	let soft_margin = budget.soft_margin.min(wall / 2);
	let max_steps = budget.max_steps;
	let started = Instant::now();
	let deadline = started + wall;

	let snapshot: Arc<Mutex<Option<Snapshot>>> = Arc::new(Mutex::new(None));
	let (tx, rx) = mpsc::channel::<Msg>();
	let worker = {
		let (cancel, stop, snapshot) = (cancel.clone(), stop.clone(), snapshot.clone());
		move || {
			let mut basis = start_basis;
			let mut step = 0u64;
			loop {
				let ctx = StepContext {
					started,
					deadline,
					soft_margin,
					step,
					cancel: cancel.clone(),
					stop: stop.clone(),
				};
				if ctx.should_stop() || max_steps.is_some_and(|m| step >= m) {
					let _ = tx.send(Msg::Idle { at: Instant::now() });
					return;
				}
				let started_at = Instant::now();
				let outcome = reducer.step(&mut basis, &ctx);
				let finished_at = Instant::now();
				if finished_at <= deadline {
					let basis = Arc::new(basis.clone());
					*snapshot.lock().unwrap_or_else(|e| e.into_inner()) =
						Some(Snapshot { step, basis });
				}
				if tx.send(Msg::Step { step, started_at, finished_at, outcome }).is_err() ||
					outcome == Step::Done
				{
					return;
				}
				step += 1;
			}
		}
	};
	thread::spawn(worker);

	let mut steps = Vec::new();
	let mut counted_steps = 0u64;
	let mut last_trace = None::<Instant>;
	// Each exit of the loop reports the termination and the instant the run
	// ended, which for the watchdog and a panic is later than the last step.
	let (termination, ended_at) = loop {
		let wait = (deadline + grace).saturating_duration_since(Instant::now());
		match rx.recv_timeout(wait) {
			Ok(Msg::Step { step, started_at, finished_at, outcome }) => {
				let counted = finished_at <= deadline;
				let mut event = StepEvent {
					step,
					elapsed_secs: finished_at.duration_since(started).as_secs_f64(),
					step_secs: finished_at.duration_since(started_at).as_secs_f64(),
					counted,
					outcome,
					approx_score_bits: None,
				};
				if counted {
					counted_steps += 1;
					let due = last_trace
						.is_none_or(|t: Instant| t.elapsed() >= budget.trace_min_interval);
					if budget.trace && due {
						// Only the newest snapshot is still available; older
						// steps go untraced when the harness thread is behind.
						let current = snapshot
							.lock()
							.unwrap_or_else(|e| e.into_inner())
							.as_ref()
							.filter(|s| s.step == step)
							.map(|s| s.basis.clone());
						if let Some(basis) = current {
							event.approx_score_bits = score_fast(instance, &basis);
							last_trace = Some(Instant::now());
						}
					}
				}
				observer.on_step(&event);
				steps.push(event);
				if !counted {
					break (Termination::Overrun, finished_at);
				}
				if outcome == Step::Done {
					break (Termination::Done, finished_at);
				}
				// The deadline is reported by the worker (`Idle`) so that every
				// step it completed in time is counted first.
				if max_steps.is_some_and(|m| step + 1 >= m) {
					break (Termination::MaxSteps, finished_at);
				}
			},
			Ok(Msg::Idle { at }) => {
				let termination = if cancel.load(Ordering::Relaxed) {
					Termination::Cancelled
				} else if max_steps.is_some_and(|m| counted_steps >= m) {
					Termination::MaxSteps
				} else {
					Termination::Deadline
				};
				break (termination, at);
			},
			Err(RecvTimeoutError::Timeout) => break (Termination::Watchdog, Instant::now()),
			Err(RecvTimeoutError::Disconnected) =>
				break (Termination::ReducerPanicked, Instant::now()),
		}
	};
	stop.store(true, Ordering::Relaxed);
	let elapsed_secs = ended_at.duration_since(started).as_secs_f64();

	let last_good = snapshot
		.lock()
		.unwrap_or_else(|e| e.into_inner())
		.take()
		.map(|s| Arc::try_unwrap(s.basis).unwrap_or_else(|b| (*b).clone()))
		.unwrap_or_else(|| instance.start_basis());
	let result = verify(instance, &last_good);
	let report = Report {
		instance: instance.descriptor(),
		reducer: name,
		budget_secs: wall.as_secs_f64(),
		grace_secs: grace.as_secs_f64(),
		elapsed_secs,
		termination,
		steps,
		counted_steps,
		result,
		basis: budget.include_basis.then_some(last_good),
	};
	observer.on_finish(&report);
	report
}

#[cfg(test)]
mod tests {
	use std::sync::atomic::AtomicU64;

	use super::*;
	use crate::instance::Variant;

	fn instance() -> Instance {
		Instance::generate(Variant::MlDsa44, [1u8; 32], 8, 6).unwrap()
	}

	fn budget(ms: u64) -> Budget {
		let mut b = Budget::new(Duration::from_millis(ms));
		b.grace = Duration::from_millis(200);
		b.soft_margin = Duration::from_millis(15);
		b
	}

	/// Swaps the first two rows on every step: a legal, visible change.
	/// Cooperative: skips its sleep when the deadline is close.
	struct Swapper;

	impl Reducer for Swapper {
		fn name(&self) -> String {
			"swapper".into()
		}
		fn step(&mut self, basis: &mut Basis, ctx: &StepContext) -> Step {
			basis.rows.swap(0, 1);
			if !ctx.should_stop() {
				thread::sleep(Duration::from_millis(5));
			}
			Step::Continue
		}
	}

	struct DoneAfter(u64);

	impl Reducer for DoneAfter {
		fn name(&self) -> String {
			"done-after".into()
		}
		fn step(&mut self, basis: &mut Basis, ctx: &StepContext) -> Step {
			basis.rows.reverse();
			if ctx.step + 1 >= self.0 {
				Step::Done
			} else {
				Step::Continue
			}
		}
	}

	/// Step 0 is quick and reverses the basis; step 1 returns after the
	/// deadline and scales a row (which would be rejected if it counted).
	struct LateSecondStep;

	impl Reducer for LateSecondStep {
		fn name(&self) -> String {
			"late".into()
		}
		fn step(&mut self, basis: &mut Basis, ctx: &StepContext) -> Step {
			if ctx.step == 0 {
				basis.rows.reverse();
			} else {
				thread::sleep(ctx.remaining() + Duration::from_millis(30));
				for x in basis.rows[0].iter_mut() {
					*x *= 2;
				}
			}
			Step::Continue
		}
	}

	/// Spins until cancelled, ignoring the deadline.
	struct Hang;

	impl Reducer for Hang {
		fn name(&self) -> String {
			"hang".into()
		}
		fn step(&mut self, _basis: &mut Basis, ctx: &StepContext) -> Step {
			while !ctx.cancelled() {
				thread::sleep(Duration::from_millis(1));
			}
			Step::Continue
		}
	}

	struct SelfCancel(Arc<AtomicBool>);

	impl Reducer for SelfCancel {
		fn name(&self) -> String {
			"self-cancel".into()
		}
		fn step(&mut self, basis: &mut Basis, ctx: &StepContext) -> Step {
			basis.rows.swap(0, 2);
			if ctx.step == 1 {
				self.0.store(true, Ordering::Relaxed);
			}
			Step::Continue
		}
	}

	struct Panics;

	impl Reducer for Panics {
		fn name(&self) -> String {
			"panics".into()
		}
		fn step(&mut self, _basis: &mut Basis, _ctx: &StepContext) -> Step {
			panic!("reducer bug");
		}
	}

	struct Cheater;

	impl Reducer for Cheater {
		fn name(&self) -> String {
			"cheater".into()
		}
		fn step(&mut self, basis: &mut Basis, _ctx: &StepContext) -> Step {
			basis.rows[0][0] += 1;
			Step::Done
		}
	}

	#[test]
	fn deadline_is_honoured_and_steps_counted() {
		let inst = instance();
		// Swapper stops sleeping once `remaining <= soft_margin`, so a step
		// can only overrun if its 5 ms sleep is delayed by more than the
		// margin. Keep the margin far above scheduler jitter on busy CI
		// runners.
		let mut b = budget(200);
		b.soft_margin = Duration::from_millis(100);
		let r = run(&inst, Swapper, &b, &mut NullObserver);
		assert_eq!(r.termination, Termination::Deadline);
		assert!(r.counted_steps >= 1, "{}", r.counted_steps);
		assert!(r.steps.iter().all(|s| s.counted));
		assert!(r.steps.iter().any(|s| s.approx_score_bits.is_some()));
		assert!(r.result.is_ok());
		assert!(r.elapsed_secs < 0.5);
		assert_eq!(r.basis.as_ref().unwrap().len(), inst.dim());
	}

	#[test]
	fn done_ends_the_run_early() {
		let inst = instance();
		let r = run(&inst, DoneAfter(3), &budget(5_000), &mut NullObserver);
		assert_eq!(r.termination, Termination::Done);
		assert_eq!(r.counted_steps, 3);
		assert_eq!(r.steps.last().unwrap().outcome, Step::Done);
		assert!(r.elapsed_secs < 1.0);
		// Three reversals leave the basis reversed.
		let mut expected = inst.start_basis();
		expected.rows.reverse();
		assert_eq!(r.basis.unwrap(), expected);
	}

	#[test]
	fn late_step_is_discarded() {
		let inst = instance();
		let r = run(&inst, LateSecondStep, &budget(40), &mut NullObserver);
		assert_eq!(r.termination, Termination::Overrun);
		assert_eq!(r.counted_steps, 1);
		assert_eq!(r.steps.len(), 2);
		assert!(!r.steps[1].counted);
		assert!(r.steps[1].approx_score_bits.is_none());
		let mut expected = inst.start_basis();
		expected.rows.reverse();
		assert_eq!(r.basis.unwrap(), expected);
		assert!(r.result.is_ok());
	}

	#[test]
	fn watchdog_terminates_a_hung_step_without_touching_the_shared_flag() {
		let inst = instance();
		let b = budget(30);
		let r = run(&inst, Hang, &b, &mut NullObserver);
		assert_eq!(r.termination, Termination::Watchdog);
		assert_eq!(r.counted_steps, 0);
		assert_eq!(r.basis.as_ref().unwrap(), &inst.start_basis());
		assert!(r.score_bits().unwrap().abs() < 1e-6);
		assert!(!b.cancel.load(Ordering::Relaxed));

		// The same budget is still usable.
		let r = run(&inst, DoneAfter(1), &b, &mut NullObserver);
		assert_eq!(r.termination, Termination::Done);
		assert_eq!(r.counted_steps, 1);
	}

	/// Swaps rows 0 and 1 on every step without sleeping, and counts its
	/// completed steps where an observer can see them.
	struct CountingSwapper(Arc<AtomicU64>);

	impl Reducer for CountingSwapper {
		fn name(&self) -> String {
			"counting-swapper".into()
		}
		fn step(&mut self, basis: &mut Basis, _ctx: &StepContext) -> Step {
			basis.rows.swap(0, 1);
			self.0.fetch_add(1, Ordering::SeqCst);
			Step::Continue
		}
	}

	/// On its first event, blocks the harness thread until the reducer has
	/// completed at least `backlog` steps, so a backlog of in-time steps
	/// builds up in the channel.
	struct BlockUntil {
		completed: Arc<AtomicU64>,
		backlog: u64,
		blocked: bool,
	}

	impl Observer for BlockUntil {
		fn on_step(&mut self, _event: &StepEvent) {
			if !self.blocked {
				self.blocked = true;
				let t = Instant::now();
				while self.completed.load(Ordering::SeqCst) < self.backlog {
					assert!(t.elapsed() < Duration::from_secs(10), "reducer stalled");
					thread::yield_now();
				}
			}
		}
	}

	#[test]
	fn slow_observer_does_not_lose_in_time_steps() {
		let inst = instance();
		let completed = Arc::new(AtomicU64::new(0));
		let mut b = budget(10_000);
		b.max_steps = Some(40);
		let mut obs = BlockUntil { completed: completed.clone(), backlog: 30, blocked: false };
		let r = run(&inst, CountingSwapper(completed), &b, &mut obs);
		assert_eq!(r.termination, Termination::MaxSteps);
		assert_eq!(r.counted_steps, 40);
		assert_eq!(r.steps.len(), 40);
		assert!(r.steps.iter().all(|s| s.counted));
		// Every step was traced from the newest snapshot or not at all; the
		// scored basis is the newest snapshot (40 swaps: unchanged).
		assert_eq!(r.basis.unwrap(), inst.start_basis());
	}

	#[test]
	fn tiny_budgets_still_run_steps() {
		let inst = instance();
		let mut b = Budget::new(Duration::from_millis(40));
		b.grace = Duration::from_millis(500);
		b.trace = false;
		assert!(b.soft_margin < b.wall / 2);
		let r = run(&inst, CountingSwapper(Arc::new(AtomicU64::new(0))), &b, &mut NullObserver);
		assert!(r.counted_steps >= 1, "{:?}", r.termination);

		let b = Budget::new(Duration::MAX);
		assert_eq!(b.wall, MAX_WALL);
	}

	/// Reverses the basis on step 0, then waits to be cancelled.
	struct HangAfterOne;

	impl Reducer for HangAfterOne {
		fn name(&self) -> String {
			"hang-after-one".into()
		}
		fn step(&mut self, basis: &mut Basis, ctx: &StepContext) -> Step {
			if ctx.step == 0 {
				basis.rows.reverse();
			} else {
				while !ctx.cancelled() {
					thread::sleep(Duration::from_millis(1));
				}
			}
			Step::Continue
		}
	}

	struct PanicsAfterOne;

	impl Reducer for PanicsAfterOne {
		fn name(&self) -> String {
			"panics-after-one".into()
		}
		fn step(&mut self, basis: &mut Basis, ctx: &StepContext) -> Step {
			if ctx.step == 0 {
				basis.rows.reverse();
				Step::Continue
			} else {
				panic!("reducer bug");
			}
		}
	}

	#[test]
	fn elapsed_time_covers_the_watchdog_wait_after_a_counted_step() {
		let inst = instance();
		let mut b = budget(60);
		b.grace = Duration::from_millis(20);
		let r = run(&inst, HangAfterOne, &b, &mut NullObserver);
		assert_eq!(r.termination, Termination::Watchdog);
		assert_eq!(r.counted_steps, 1);
		assert!(r.elapsed_secs >= 0.08, "{}", r.elapsed_secs);
		let mut expected = inst.start_basis();
		expected.rows.reverse();
		assert_eq!(r.basis.unwrap(), expected);
	}

	#[test]
	fn panic_after_a_counted_step_keeps_the_snapshot() {
		let inst = instance();
		let r = run(&inst, PanicsAfterOne, &budget(5_000), &mut NullObserver);
		assert_eq!(r.termination, Termination::ReducerPanicked);
		assert_eq!(r.counted_steps, 1);
		assert!(r.elapsed_secs >= r.steps[0].elapsed_secs);
		let mut expected = inst.start_basis();
		expected.rows.reverse();
		assert_eq!(r.basis.unwrap(), expected);
		assert!(r.result.is_ok());
	}

	#[test]
	fn cancel_flag_stops_after_current_step() {
		let inst = instance();
		let b = budget(5_000);
		let r = run(&inst, SelfCancel(b.cancel.clone()), &b, &mut NullObserver);
		assert_eq!(r.termination, Termination::Cancelled);
		assert_eq!(r.counted_steps, 2);
	}

	#[test]
	fn max_steps_is_enforced() {
		let inst = instance();
		let mut b = budget(5_000);
		b.max_steps = Some(4);
		let r = run(&inst, Swapper, &b, &mut NullObserver);
		assert_eq!(r.termination, Termination::MaxSteps);
		assert_eq!(r.counted_steps, 4);
	}

	#[test]
	fn panicking_reducer_is_scored_on_start_basis() {
		let inst = instance();
		let r = run(&inst, Panics, &budget(1_000), &mut NullObserver);
		assert_eq!(r.termination, Termination::ReducerPanicked);
		assert_eq!(r.counted_steps, 0);
		assert!(r.score_bits().unwrap().abs() < 1e-6);
	}

	#[test]
	fn invalid_output_is_rejected_not_scored() {
		let inst = instance();
		let r = run(&inst, Cheater, &budget(1_000), &mut NullObserver);
		assert_eq!(r.termination, Termination::Done);
		assert_eq!(r.result, Err(Rejection::NotInLattice { row: 0 }));
		assert!(r.score_bits().is_none());
	}

	#[test]
	fn jsonl_observer_emits_parseable_events_and_report_round_trips() {
		let inst = instance();
		let mut obs = JsonlObserver::new(Vec::new());
		let mut b = budget(5_000);
		b.max_steps = Some(2);
		let r = run(&inst, Swapper, &b, &mut obs);
		let out = String::from_utf8(obs.finish().unwrap()).unwrap();
		let lines: Vec<serde_json::Value> =
			out.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
		assert_eq!(lines.len(), 4);
		assert_eq!(lines[0]["event"], "start");
		assert_eq!(lines[1]["event"], "step");
		assert_eq!(lines[3]["event"], "finish");
		assert_eq!(lines[3]["termination"], "MaxSteps");

		let json = serde_json::to_string(&r).unwrap();
		let back: Report = serde_json::from_str(&json).unwrap();
		assert_eq!(back, r);
	}

	/// Accepts one line, then fails.
	#[derive(Debug)]
	struct FailAfterOne {
		buf: Vec<u8>,
		lines: usize,
	}

	impl Write for FailAfterOne {
		fn write(&mut self, data: &[u8]) -> io::Result<usize> {
			if self.lines >= 1 {
				return Err(io::Error::other("disk full"));
			}
			self.lines += 1;
			self.buf.extend_from_slice(data);
			Ok(data.len())
		}
		fn flush(&mut self) -> io::Result<()> {
			Ok(())
		}
	}

	#[test]
	fn jsonl_observer_reports_write_errors_and_stops_writing() {
		let inst = instance();
		let mut obs = JsonlObserver::new(FailAfterOne { buf: Vec::new(), lines: 0 });
		let mut b = budget(5_000);
		b.max_steps = Some(2);
		run(&inst, Swapper, &b, &mut obs);
		assert!(obs.error().is_some());
		let err = obs.finish().unwrap_err();
		assert_eq!(err.to_string(), "disk full");
	}
}
