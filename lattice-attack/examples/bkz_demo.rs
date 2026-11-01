//! Run the reference progressive BKZ on a seeded instance under a time budget
//! and write the report, or re-verify a previously written report offline.
//!
//! ```text
//! cargo run --release -p qp-rusty-crystals-lattice-attack --example bkz_demo -- \
//!     --variant 44 --seed 00 --n 60 --m 60 --secs 30 --report report.json --events events.jsonl
//! cargo run --release -p qp-rusty-crystals-lattice-attack --example bkz_demo -- --verify report.json
//! ```

use std::{
	fs::File,
	io::{BufWriter, Write},
	process::ExitCode,
	time::Duration,
};

use qp_rusty_crystals_lattice_attack::{
	harness::{run, Budget, JsonlObserver, Observer, Report, StderrObserver, StepEvent},
	instance::InstanceDescriptor,
	reducers::ProgressiveBkz,
	verify::verify,
	Instance, Variant,
};

struct Args {
	variant: Variant,
	seed: [u8; 32],
	n: usize,
	m: usize,
	wall: Duration,
	beta_start: usize,
	beta_max: usize,
	report: Option<String>,
	events: Option<String>,
	include_basis: bool,
	trace: bool,
	verify: Option<String>,
}

/// Up to 32 bytes of hex; shorter input is padded with zero bytes at the
/// end, so `07` is `[7, 0, 0, …]`.
fn parse_seed(s: &str) -> Result<[u8; 32], String> {
	let bytes = hex::decode(s.trim_start_matches("0x")).map_err(|e| format!("seed: {e}"))?;
	if bytes.len() > 32 {
		return Err("seed must be at most 32 bytes of hex".into());
	}
	let mut out = [0u8; 32];
	out[..bytes.len()].copy_from_slice(&bytes);
	Ok(out)
}

fn parse_secs(s: &str) -> Result<Duration, String> {
	let secs: f64 = s.parse().map_err(|e| format!("--secs: {e}"))?;
	Duration::try_from_secs_f64(secs).map_err(|e| format!("--secs: {e}"))
}

fn parse_args() -> Result<Args, String> {
	let mut a = Args {
		variant: Variant::MlDsa44,
		seed: [0u8; 32],
		n: 60,
		m: 60,
		wall: Duration::from_secs(30),
		beta_start: 10,
		beta_max: 60,
		report: None,
		events: None,
		include_basis: true,
		trace: true,
		verify: None,
	};
	let mut it = std::env::args().skip(1);
	while let Some(flag) = it.next() {
		let mut value = || it.next().ok_or(format!("{flag} needs a value"));
		match flag.as_str() {
			"--variant" => a.variant = value()?.parse().map_err(|e| format!("{e}"))?,
			"--seed" => a.seed = parse_seed(&value()?)?,
			"--n" => a.n = value()?.parse().map_err(|e| format!("--n: {e}"))?,
			"--m" => a.m = value()?.parse().map_err(|e| format!("--m: {e}"))?,
			"--secs" => a.wall = parse_secs(&value()?)?,
			"--beta" => {
				let v = value()?;
				let (lo, hi) = v.split_once("..").ok_or("--beta expects START..MAX")?;
				a.beta_start = lo.parse().map_err(|e| format!("--beta: {e}"))?;
				a.beta_max = hi.parse().map_err(|e| format!("--beta: {e}"))?;
			},
			"--report" => a.report = Some(value()?),
			"--events" => a.events = Some(value()?),
			"--no-basis" => a.include_basis = false,
			"--no-trace" => a.trace = false,
			"--verify" => a.verify = Some(value()?),
			"--help" | "-h" => return Err(USAGE.into()),
			other => return Err(format!("unknown flag {other}\n{USAGE}")),
		}
	}
	Ok(a)
}

const USAGE: &str = "usage: bkz_demo [--variant 44|65|87] [--seed HEX] [--n N] [--m M] [--secs S] \
                     [--beta START..MAX] [--report FILE] [--events FILE] [--no-basis] [--no-trace]\n       \
                     bkz_demo --verify REPORT";

fn main() -> ExitCode {
	let args = match parse_args() {
		Ok(a) => a,
		Err(e) => {
			eprintln!("{e}");
			return ExitCode::from(2);
		},
	};
	if let Some(path) = &args.verify {
		return reverify(path);
	}

	let instance = match Instance::generate(args.variant, args.seed, args.n, args.m) {
		Ok(i) => i,
		Err(e) => {
			eprintln!("{e}");
			return ExitCode::from(2);
		},
	};
	let mut budget = Budget::new(args.wall);
	budget.include_basis = args.include_basis;
	budget.trace = args.trace;
	let reducer = ProgressiveBkz::new(args.beta_start, args.beta_max);

	let mut events = match &args.events {
		Some(path) => match File::create(path) {
			Ok(f) => Some(JsonlObserver::new(BufWriter::new(f))),
			Err(e) => {
				eprintln!("cannot create {path}: {e}");
				return ExitCode::from(2);
			},
		},
		None => None,
	};
	let mut stderr = StderrObserver;
	let mut observers: Vec<&mut dyn Observer> = vec![&mut stderr];
	if let Some(ev) = &mut events {
		observers.push(ev);
	}
	let report = run(&instance, reducer, &budget, &mut Fanout(observers));

	let mut failed = false;
	if let Some(ev) = events {
		if let Err(e) = ev.finish() {
			eprintln!("cannot write {}: {e}", args.events.as_deref().unwrap_or_default());
			failed = true;
		}
	}
	if let Some(path) = &args.report {
		if let Err(e) = write_report(path, &report) {
			eprintln!("cannot write {path}: {e}");
			failed = true;
		}
	}
	if report.result.is_ok() && !failed {
		ExitCode::SUCCESS
	} else {
		ExitCode::from(1)
	}
}

fn write_report(path: &str, report: &Report) -> std::io::Result<()> {
	let mut w = BufWriter::new(File::create(path)?);
	serde_json::to_writer(&mut w, report)?;
	w.flush()
}

/// Re-run the verifier on the basis stored in a report, regenerating the
/// instance from its descriptor.
fn reverify(path: &str) -> ExitCode {
	let report: Report = match File::open(path).map_err(|e| e.to_string()).and_then(|f| {
		serde_json::from_reader(std::io::BufReader::new(f)).map_err(|e| e.to_string())
	}) {
		Ok(r) => r,
		Err(e) => {
			eprintln!("cannot read {path}: {e}");
			return ExitCode::from(2);
		},
	};
	let Some(basis) = &report.basis else {
		eprintln!("report has no basis (run without --no-basis)");
		return ExitCode::from(2);
	};
	let Some(seed_hex) = &report.instance.seed else {
		eprintln!("report instance was imported from a public key; cannot regenerate");
		return ExitCode::from(2);
	};
	let seed = match parse_seed(seed_hex) {
		Ok(s) => s,
		Err(e) => {
			eprintln!("bad seed in report: {e}");
			return ExitCode::from(2);
		},
	};
	let d = &report.instance;
	let instance = match Instance::generate(d.variant, seed, d.n, d.m) {
		Ok(i) => i,
		Err(e) => {
			eprintln!("{e}");
			return ExitCode::from(2);
		},
	};
	if instance.id_hex() != d.id {
		eprintln!("instance id mismatch: report says {}, regenerated {}", d.id, instance.id_hex());
		return ExitCode::from(1);
	}
	match verify(&instance, basis) {
		Ok(score) => {
			let claimed = report.score_bits();
			println!(
				"verified: {:.3} bits (report claimed {}), |b1| = {:.1}, {:.3}×GH",
				score.score_bits,
				claimed.map(|c| format!("{c:.3}")).unwrap_or_else(|| "rejection".into()),
				score.first_norm,
				score.first_over_gh
			);
			match claimed {
				Some(c) if (c - score.score_bits).abs() < 1e-6 => ExitCode::SUCCESS,
				_ => ExitCode::from(1),
			}
		},
		Err(e) => {
			println!("rejected: {e}");
			ExitCode::from(1)
		},
	}
}

struct Fanout<'a>(Vec<&'a mut dyn Observer>);

impl Observer for Fanout<'_> {
	fn on_start(&mut self, instance: &InstanceDescriptor, reducer: &str, budget: &Budget) {
		for o in &mut self.0 {
			o.on_start(instance, reducer, budget);
		}
	}

	fn on_step(&mut self, event: &StepEvent) {
		for o in &mut self.0 {
			o.on_step(event);
		}
	}

	fn on_finish(&mut self, report: &Report) {
		for o in &mut self.0 {
			o.on_finish(report);
		}
	}
}
