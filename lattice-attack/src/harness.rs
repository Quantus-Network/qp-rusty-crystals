//! Runs a [`Reducer`] against an instance under a wall-clock budget and hands
//! the result to the verifier.
//!
//! The harness owns the clock. The reducer runs on a worker thread and sends
//! a snapshot of the basis after every step; only snapshots that arrive
//! before the deadline count. If a step is still running `grace` after the
//! deadline, a watchdog ends the run on the last counted snapshot.

use std::{
	io::Write,
	sync::{
		atomic::{AtomicBool, Ordering},
		mpsc::{self, RecvTimeoutError},
		Arc,
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
	pub deadline: Instant,
	/// Zero-based index of this step.
	pub step: u64,
	cancel: Arc<AtomicBool>,
}

impl StepContext {
	pub fn remaining(&self) -> Duration {
		self.deadline.saturating_duration_since(Instant::now())
	}

	pub fn elapsed(&self) -> Duration {
		self.started.elapsed()
	}

	/// True once the deadline has passed or the run was cancelled. Reducers
	/// doing long inner loops should poll this and return promptly.
	pub fn should_stop(&self) -> bool {
		self.cancelled() || Instant::now() >= self.deadline
	}

	pub fn cancelled(&self) -> bool {
		self.cancel.load(Ordering::Relaxed)
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
	/// Wall-clock allowance measured from just before the first step.
	pub wall: Duration,
	/// How long past the deadline to wait for an in-flight step before the
	/// watchdog gives up on it.
	pub grace: Duration,
	pub max_steps: Option<u64>,
	/// Compute an approximate `f64` score after each counted step (costs
	/// `O(d³)` per step; fine for small instances, disable for large ones).
	pub trace: bool,
	/// Minimum spacing between trace computations.
	pub trace_min_interval: Duration,
	/// Attach the final basis to the report so it can be re-verified offline.
	pub include_basis: bool,
	/// Set to `true` from anywhere to stop the run after the current step.
	pub cancel: Arc<AtomicBool>,
}

impl Budget {
	pub fn new(wall: Duration) -> Self {
		Budget {
			wall,
			grace: Duration::from_secs(5),
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

/// One JSON object per line: `start`, `step`, and `finish` events.
pub struct JsonlObserver<W: Write> {
	out: W,
}

impl<W: Write> JsonlObserver<W> {
	pub fn new(out: W) -> Self {
		JsonlObserver { out }
	}

	fn emit<T: Serialize>(&mut self, event: &str, payload: &T) {
		#[derive(Serialize)]
		struct Line<'a, T> {
			event: &'a str,
			#[serde(flatten)]
			payload: &'a T,
		}
		if serde_json::to_writer(&mut self.out, &Line { event, payload }).is_ok() {
			let _ = self.out.write_all(b"\n");
		}
	}

	pub fn into_inner(self) -> W {
		self.out
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
		basis: Basis,
	},
	/// The worker saw the deadline or cancel flag before starting a step.
	Idle,
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
	let mut last_good = start_basis.clone();
	let cancel = budget.cancel.clone();
	let started = Instant::now();
	let deadline = started + budget.wall;
	let max_steps = budget.max_steps;

	let (tx, rx) = mpsc::channel::<Msg>();
	let worker_cancel = cancel.clone();
	thread::spawn(move || {
		let mut basis = start_basis;
		let mut step = 0u64;
		loop {
			let ctx = StepContext { started, deadline, step, cancel: worker_cancel.clone() };
			if ctx.should_stop() || max_steps.is_some_and(|m| step >= m) {
				let _ = tx.send(Msg::Idle);
				return;
			}
			let started_at = Instant::now();
			let outcome = reducer.step(&mut basis, &ctx);
			let finished_at = Instant::now();
			let msg = Msg::Step { step, started_at, finished_at, outcome, basis: basis.clone() };
			if tx.send(msg).is_err() || outcome == Step::Done {
				return;
			}
			step += 1;
		}
	});

	let mut steps = Vec::new();
	let mut counted_steps = 0u64;
	let mut last_trace = None::<Instant>;
	let termination = loop {
		let wait = (deadline + budget.grace).saturating_duration_since(Instant::now());
		match rx.recv_timeout(wait) {
			Ok(Msg::Step { step, started_at, finished_at, outcome, basis }) => {
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
						event.approx_score_bits = score_fast(instance, &basis);
						last_trace = Some(Instant::now());
					}
					last_good = basis;
				}
				observer.on_step(&event);
				steps.push(event);
				if !counted {
					break Termination::Overrun;
				}
				if outcome == Step::Done {
					break Termination::Done;
				}
				// Cancellation is reported by the worker (`Idle`) so that a
				// step it already completed in time is still counted.
				if max_steps.is_some_and(|m| step + 1 >= m) {
					break Termination::MaxSteps;
				}
				if Instant::now() >= deadline {
					break Termination::Deadline;
				}
			},
			Ok(Msg::Idle) =>
				break if cancel.load(Ordering::Relaxed) {
					Termination::Cancelled
				} else if max_steps.is_some_and(|m| counted_steps >= m) {
					Termination::MaxSteps
				} else {
					Termination::Deadline
				},
			Err(RecvTimeoutError::Timeout) => {
				cancel.store(true, Ordering::Relaxed);
				break Termination::Watchdog;
			},
			Err(RecvTimeoutError::Disconnected) => break Termination::ReducerPanicked,
		}
	};
	let elapsed_secs = started.elapsed().as_secs_f64();

	let result = verify(instance, &last_good);
	let report = Report {
		instance: instance.descriptor(),
		reducer: name,
		budget_secs: budget.wall.as_secs_f64(),
		grace_secs: budget.grace.as_secs_f64(),
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
	use super::*;
	use crate::instance::Variant;

	fn instance() -> Instance {
		Instance::generate(Variant::MlDsa44, [1u8; 32], 8, 6).unwrap()
	}

	fn budget(ms: u64) -> Budget {
		let mut b = Budget::new(Duration::from_millis(ms));
		b.grace = Duration::from_millis(200);
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
			if ctx.remaining() > Duration::from_millis(20) {
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
		let r = run(&inst, Swapper, &budget(60), &mut NullObserver);
		assert_eq!(r.termination, Termination::Deadline);
		assert!(r.counted_steps >= 2, "{}", r.counted_steps);
		assert!(r.steps.iter().all(|s| s.counted && s.approx_score_bits.is_some()));
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
	fn watchdog_terminates_a_hung_step() {
		let inst = instance();
		let b = budget(30);
		let r = run(&inst, Hang, &b, &mut NullObserver);
		assert_eq!(r.termination, Termination::Watchdog);
		assert_eq!(r.counted_steps, 0);
		assert!(b.cancel.load(Ordering::Relaxed));
		assert_eq!(r.basis.as_ref().unwrap(), &inst.start_basis());
		assert!(r.score_bits().unwrap().abs() < 1e-6);
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
		let out = String::from_utf8(obs.into_inner()).unwrap();
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
}
