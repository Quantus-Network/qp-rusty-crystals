use qp_rusty_crystals_dilithium::ml_dsa_87;
#[cfg(debug_assertions)]
use qp_rusty_crystals_dilithium::{
	params,
	poly::Poly,
	polyvec::{Polyveck, Polyvecl},
};
use std::{
	alloc::{GlobalAlloc, Layout, System},
	sync::atomic::{AtomicUsize, Ordering},
};

struct TrackingAllocator;
static HEAP_ACTIVE: AtomicUsize = AtomicUsize::new(0);
static HEAP_PEAK: AtomicUsize = AtomicUsize::new(0);

#[global_allocator]
static ALLOC: TrackingAllocator = TrackingAllocator;

unsafe impl GlobalAlloc for TrackingAllocator {
	unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
		let ptr = System.alloc(layout);
		if !ptr.is_null() {
			let a = HEAP_ACTIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
			HEAP_PEAK.fetch_max(a, Ordering::Relaxed);
		}
		ptr
	}
	unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
		HEAP_ACTIVE.fetch_sub(layout.size(), Ordering::Relaxed);
		System.dealloc(ptr, layout);
	}
	unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
		HEAP_ACTIVE.fetch_sub(layout.size(), Ordering::Relaxed);
		let p = System.realloc(ptr, layout, new_size);
		if !p.is_null() {
			let a = HEAP_ACTIVE.fetch_add(new_size, Ordering::Relaxed) + new_size;
			HEAP_PEAK.fetch_max(a, Ordering::Relaxed);
		} else {
			HEAP_ACTIVE.fetch_add(layout.size(), Ordering::Relaxed);
		}
		p
	}
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn get_sp() -> usize {
	let sp: usize;
	unsafe { core::arch::asm!("mov {}, rsp", out(reg) sp) }
	sp
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn get_sp() -> usize {
	let sp: usize;
	unsafe { core::arch::asm!("mov {}, sp", out(reg) sp) }
	sp
}

const PAINT: u8 = 0xCD;
const PAINT_SIZE: usize = 3 * 1024 * 1024;

struct MemUsage {
	stack: usize,
	heap_peak: usize,
}

fn measure<F, R>(f: F) -> (R, MemUsage)
where
	F: FnOnce() -> R + Send + 'static,
	R: Send + 'static,
{
	std::thread::Builder::new()
		.stack_size(4 * 1024 * 1024)
		.spawn(move || paint_and_measure(f))
		.unwrap()
		.join()
		.unwrap()
}

#[inline(never)]
fn paint_and_measure<F: FnOnce() -> R, R>(f: F) -> (R, MemUsage) {
	let sp = get_sp();
	let bottom = sp - PAINT_SIZE;
	unsafe { core::ptr::write_bytes(bottom as *mut u8, PAINT, PAINT_SIZE) }

	HEAP_PEAK.store(HEAP_ACTIVE.load(Ordering::SeqCst), Ordering::SeqCst);
	let heap_base = HEAP_ACTIVE.load(Ordering::SeqCst);

	let result = std::hint::black_box(f());

	let heap_delta = HEAP_PEAK.load(Ordering::SeqCst).saturating_sub(heap_base);

	let mut untouched = 0usize;
	unsafe {
		let p = bottom as *const u8;
		for i in 0..PAINT_SIZE {
			if core::ptr::read_volatile(p.add(i)) == PAINT {
				untouched += 1;
			} else {
				break;
			}
		}
	}

	(result, MemUsage { stack: PAINT_SIZE - untouched, heap_peak: heap_delta })
}

const MSG: &[u8] = b"memory measurement test";

fn main() {
	println!("=== ML-DSA-87 Memory Measurement ===");
	println!("Method: stack painting (watermark) + heap tracking allocator\n");

	#[cfg(feature = "embedded")]
	println!("Feature: embedded (large structs boxed to heap)");
	#[cfg(not(feature = "embedded"))]
	println!("Feature: default (all structs on stack)");

	#[cfg(debug_assertions)]
	println!("Build:   DEBUG (run with --release for production-accurate numbers)");
	#[cfg(not(debug_assertions))]
	println!("Build:   RELEASE");

	#[cfg(debug_assertions)]
	{
		println!("\nData structure sizes:");
		println!("  Poly:       {:>6} bytes", std::mem::size_of::<Poly>());
		println!("  Polyvecl:   {:>6} bytes (L={})", std::mem::size_of::<Polyvecl>(), params::L);
		println!("  Polyveck:   {:>6} bytes (K={})", std::mem::size_of::<Polyveck>(), params::K);
		println!("  PublicKey:  {:>6} bytes", params::PUBLICKEYBYTES);
		println!("  SecretKey:  {:>6} bytes", params::SECRETKEYBYTES);
		println!("  Signature:  {:>6} bytes", params::SIGNBYTES);
	}

	let kp = ml_dsa_87::Keypair::generate((&mut [1u8; 32]).into());
	let sig = kp.sign(MSG, None, None).unwrap();

	let (_, keygen_mem) = measure(|| ml_dsa_87::Keypair::generate((&mut [1u8; 32]).into()));

	let kp_box = Box::new(kp.clone());
	let (_, sign_mem) = measure(move || kp_box.sign(MSG, None, None).unwrap());

	let pk_box = Box::new(kp.public.clone());
	let sig_box = Box::new(sig);
	let (_, verify_mem) = measure(move || pk_box.verify(MSG, sig_box.as_ref(), None));

	println!("\n{:<18} {:>10} {:>12} {:>10}", "Operation", "Stack", "Heap Peak", "Total");
	println!("{:-<18}-{:->10}-{:->12}-{:->10}", "", "", "", "");
	for (name, m) in
		[("Key Generation", &keygen_mem), ("Signing", &sign_mem), ("Verification", &verify_mem)]
	{
		let total = m.stack + m.heap_peak;
		println!(
			"{:<18} {:>7.1} KB {:>9.1} KB {:>7.1} KB",
			name,
			m.stack as f64 / 1024.0,
			m.heap_peak as f64 / 1024.0,
			total as f64 / 1024.0,
		);
	}

	let max = [&keygen_mem, &sign_mem, &verify_mem]
		.iter()
		.map(|m| m.stack + m.heap_peak)
		.max()
		.unwrap();
	println!("\nPeak total memory: {:.1} KB ({} bytes)", max as f64 / 1024.0, max);
}
