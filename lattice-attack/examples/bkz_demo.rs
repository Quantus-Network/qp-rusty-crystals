//! Run the reference progressive BKZ on a seeded instance under a time budget
//! and write the report, or re-verify a previously written report offline.
//!
//! ```text
//! cargo run --release -p qp-rusty-crystals-lattice-attack --example bkz_demo -- \
//!     --variant 44 --seed 00 --n 60 --m 60 --secs 30 --report report.json --events events.jsonl
//! cargo run --release -p qp-rusty-crystals-lattice-attack --example bkz_demo -- --verify report.json
//! ```

use std::{fs::File, io::BufWriter, process::ExitCode, time::Duration};

use qp_rusty_crystals_lattice_attack::{
	harness::{run, Budget, JsonlObserver, Observer, Report, StderrObserver},
	reducers::ProgressiveBkz,
	verify::verify,
	Instance, Variant,
};

struct Args {
	variant: Variant,
	seed: [u8; 32],
	n: usize,
	m: usize,
	secs: f64,
	beta_start: usize,
	beta_max: usize,
	report: Option<String>,
	events: Option<String>,
	include_basis: bool,
	trace: bool,
	verify: Option<String>,
}

fn parse_seed(s: &str) -> Result<[u8; 32], String> {
	let s = s.trim_start_matches("0x");
	if s.len() > 64 || !s.len().is_multiple_of(2) {
		return Err("seed must be at most 32 bytes of hex".into());
	}
	let mut out = [0u8; 32];
	for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
		let hex = std::str::from_utf8(chunk).map_err(|e| e.to_string())?;
		out[i] = u8::from_str_radix(hex, 16).map_err(|e| e.to_string())?;
	}
	Ok(out)
}

fn parse_args() -> Result<Args, String> {
	let mut a = Args {
		variant: Variant::MlDsa44,
		seed: [0u8; 32],
		n: 60,
		m: 60,
		secs: 30.0,
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
			"--secs" => a.secs = value()?.parse().map_err(|e| format!("--secs: {e}"))?,
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
	let mut budget = Budget::new(Duration::from_secs_f64(args.secs));
	budget.include_basis = args.include_basis;
	budget.trace = args.trace;
	let reducer = ProgressiveBkz::new(args.beta_start, args.beta_max);

	let mut observers: Vec<Box<dyn Observer>> = vec![Box::new(StderrObserver)];
	if let Some(path) = &args.events {
		match File::create(path) {
			Ok(f) => observers.push(Box::new(JsonlObserver::new(BufWriter::new(f)))),
			Err(e) => {
				eprintln!("cannot create {path}: {e}");
				return ExitCode::from(2);
			},
		}
	}
	let mut fanout = Fanout(observers);
	let report = run(&instance, reducer, &budget, &mut fanout);

	if let Some(path) = &args.report {
		match File::create(path).map(BufWriter::new) {
			Ok(w) =>
				if let Err(e) = serde_json::to_writer(w, &report) {
					eprintln!("cannot write {path}: {e}");
					return ExitCode::from(1);
				},
			Err(e) => {
				eprintln!("cannot create {path}: {e}");
				return ExitCode::from(1);
			},
		}
	}
	if report.result.is_ok() {
		ExitCode::SUCCESS
	} else {
		ExitCode::from(1)
	}
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

struct Fanout(Vec<Box<dyn Observer>>);

impl Observer for Fanout {
	fn on_start(
		&mut self,
		instance: &qp_rusty_crystals_lattice_attack::instance::InstanceDescriptor,
		reducer: &str,
		budget: &Budget,
	) {
		for o in &mut self.0 {
			o.on_start(instance, reducer, budget);
		}
	}

	fn on_step(&mut self, event: &qp_rusty_crystals_lattice_attack::harness::StepEvent) {
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
