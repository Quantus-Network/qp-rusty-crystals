//! Regression tests (security review): dropped `bip39::Mnemonic` values must
//! not leave the mnemonic's word indices in dead stack memory.
//!
//! `Mnemonic` stores the secret phrase as `words: [u16; 24]` (indices into the
//! public BIP39 word list, so the phrase is trivially reconstructible from
//! them) and only implements `Zeroize`/`ZeroizeOnDrop` when the bip39 crate's
//! `zeroize` feature is enabled. The workspace previously declared bip39 with
//! `default-features = false` and no `zeroize` feature, so the `Mnemonic`
//! locals dropped inside `mnemonic_to_seed` (seed stretching) and
//! `generate_mnemonic` left the full word-index buffer in dead stack frames.
//!
//! Detection uses the same painted-stack technique as the other
//! `*_stack_zeroization` tests: run the operation on a sentinel-painted buffer
//! via `psm::on_stack`, then scan the buffer — which we own, so the read is
//! sound — for the native-endian byte image of the expected word-index array.
//!
//! The assertion is about codegen (which temporaries get wiped), so it is only
//! compiled for optimized builds (`cargo test --release`): unoptimized codegen
//! materializes additional compiler-generated move temporaries that no
//! source-level fix can wipe.
#![cfg(not(debug_assertions))]

use std::alloc::{alloc, dealloc, Layout};

use bip39::Language;
use qp_rusty_crystals_hdwallet::{
	generate_mnemonic, mnemonic_to_seed, SensitiveBytes32, SensitiveBytes64,
};

const PAINT: u8 = 0xAA;
// 4 MiB: comfortably above what PBKDF2 seed stretching needs.
const STACK_BYTES: usize = 4 * 1024 * 1024;
const ALIGN: usize = 4096;

/// Run `f` on a freshly painted stack buffer, then scan the buffer for
/// `pattern` and return whether it was found.
fn probe_stack_for<F: FnOnce()>(pattern: &[u8], f: F) -> bool {
	let layout = Layout::from_size_align(STACK_BYTES, ALIGN).unwrap();
	unsafe {
		let base = alloc(layout);
		assert!(!base.is_null(), "probe stack allocation failed");
		std::ptr::write_bytes(base, PAINT, STACK_BYTES);

		psm::on_stack(base, STACK_BYTES, f);

		let region = std::slice::from_raw_parts(base, STACK_BYTES);
		let offsets: Vec<usize> = region
			.windows(pattern.len())
			.enumerate()
			.filter(|(_, w)| w == &pattern)
			.map(|(i, _)| i)
			.collect();
		eprintln!("probe: {} match(es) at offsets {:?}", offsets.len(), offsets);
		let found = !offsets.is_empty();
		dealloc(base, layout);
		found
	}
}

/// The in-memory image of `Mnemonic`'s `words: [u16; 24]` buffer for `phrase`:
/// each word's index into the English word list, in native endianness.
fn word_index_pattern(phrase: &str) -> Vec<u8> {
	let words: Vec<&str> = phrase.split_whitespace().collect();
	assert_eq!(words.len(), 24, "test phrases must use all 24 word slots");
	words
		.iter()
		.flat_map(|w| {
			Language::English
				.find_word(w)
				.unwrap_or_else(|| panic!("{w:?} is not a BIP39 word"))
				.to_ne_bytes()
		})
		.collect()
}

const PHRASE: &str = "panda eyebrow bullet gorilla call smoke muffin taste mesh \
	discover soft ostrich alcohol speed nation flash devote level hobby quick \
	inner drive ghost inside";

#[test]
fn mnemonic_word_indices_never_survive_on_the_stack() {
	let pattern = word_index_pattern(PHRASE);

	// Sanity: the technique detects an unwiped Mnemonic. A closure that
	// parses one and skips its destructor must be seen.
	assert!(
		probe_stack_for(&pattern, || {
			let mnemonic = bip39::Mnemonic::parse_in_normalized(Language::English, PHRASE).unwrap();
			core::mem::forget(mnemonic);
		}),
		"probe self-check: a deliberately leaked Mnemonic was not detected"
	);

	// Scenario A: seed stretching. The Mnemonic parsed inside is dropped
	// after PBKDF2; its word-index buffer must not survive.
	let phrase = PHRASE.to_string();
	let seed_stretch_leaked = probe_stack_for(&pattern, move || {
		let mut seed = SensitiveBytes64::zeroed();
		mnemonic_to_seed(phrase, None, &mut seed).unwrap();
		core::hint::black_box(&seed);
	});

	// Scenario B: mnemonic generation. The Mnemonic built from entropy is
	// dropped after the phrase string is produced; same requirement. The
	// expected pattern is computed from a non-probed run with the same
	// entropy (generation is deterministic in the entropy).
	let entropy = [0x27u8; 32];
	let generated = generate_mnemonic(SensitiveBytes32::from(&mut { entropy })).unwrap();
	let generated_pattern = word_index_pattern(&generated);
	let generation_leaked = probe_stack_for(&generated_pattern, || {
		let phrase = generate_mnemonic(SensitiveBytes32::from(&mut { entropy })).unwrap();
		core::hint::black_box(&phrase);
	});

	assert!(
		!seed_stretch_leaked,
		"mnemonic_to_seed() left the mnemonic word indices in dead stack memory; \
		 the phrase is reconstructible from them and yields the whole HD wallet"
	);
	assert!(
		!generation_leaked,
		"generate_mnemonic() left the mnemonic word indices in dead stack memory; \
		 the phrase is reconstructible from them and yields the whole HD wallet"
	);
}

// Regression test (security review): the seed produced by `mnemonic_to_seed`
// must leave no copy in memory once the caller's `SensitiveBytes64` is
// dropped — with no manual zeroization hygiene on the caller's part. The seed
// yields the entire HD wallet.
//
// This is why the API writes into a caller-provided `SensitiveBytes64`
// instead of returning the seed by value: a by-value return is moved (i.e.
// copied) through the `Result` payload and return slot, and moved-from stack
// slots are dead but never dropped, so `ZeroizeOnDrop` cannot wipe them. With
// the out-parameter the secret only ever exists inside the caller's wiping
// guard, and this probe asserts exactly that: zero residue.
#[test]
fn seed_produced_by_mnemonic_to_seed_wipes_itself_on_drop() {
	// Expected seed bytes, computed outside the probed region.
	let mut expected_holder = SensitiveBytes64::zeroed();
	mnemonic_to_seed(PHRASE.to_string(), None, &mut expected_holder).unwrap();
	let expected = *expected_holder.as_bytes();

	let phrase = PHRASE.to_string();
	let leaked = probe_stack_for(&expected[..], move || {
		let mut seed = SensitiveBytes64::zeroed();
		mnemonic_to_seed(phrase, None, &mut seed).unwrap();
		core::hint::black_box(&seed);
		// `seed` drops here and wipes its interior in place.
	});
	assert!(
		!leaked,
		"the seed produced by mnemonic_to_seed() survived in dead stack memory \
		 after the caller's SensitiveBytes64 was dropped"
	);
}
