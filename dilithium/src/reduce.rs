use crate::params::Q;

/// Inverse of Q modulo 2^32.
const Q_INV: i32 = 58728449;

/// The domain is half-open (security review): at exactly a = 2^31 * Q the
/// signed low word `a * Q_INV mod± 2^32` truncates to `i32::MIN` (Q is odd),
/// and `(a - i32::MIN * Q) >> 32` evaluates to exactly `Q` — the
/// representative the output contract excludes. The negative endpoint is
/// safe (it reduces to 0), so it stays inclusive.
pub fn montgomery_reduce(a: i64) -> i32 {
	let t = (a as i32).wrapping_mul(Q_INV);
	((a - t as i64 * Q as i64) >> 32) as i32
}

/// Reduces `a <= 2^31 - 2^22 - 1` to a representative modulo Q in `[-6283008, 6283008]`.
pub fn reduce32(a: i32) -> i32 {
	let t = (a + (1 << 22)) >> 23;
	a - t * Q
}

/// Adds Q to a negative `a`, branch-free.
pub fn caddq(a: i32) -> i32 {
	a + ((a >> 31) & Q)
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Deterministic 64-bit generator (xorshift) for spread-out test inputs.
	fn samples() -> impl Iterator<Item = u64> {
		let mut x = 0x9E37_79B9_7F4A_7C15u64;
		core::iter::repeat_with(move || {
			x ^= x << 13;
			x ^= x >> 7;
			x ^= x << 17;
			x
		})
		.take(10_000)
	}

	#[test]
	fn q_inv_inverts_q_modulo_2_32() {
		assert_eq!(Q.wrapping_mul(Q_INV), 1);
	}

	/// `r * 2^32 = a (mod Q)` and `-Q < r < Q` over the whole input domain.
	#[test]
	fn montgomery_reduce_congruence_and_range() {
		let q = Q as i128;
		let bound = (1i64 << 31) * Q as i64;
		for a in samples().map(|x| (x % (2 * bound as u64)) as i64 - bound).chain([-bound, 0]) {
			let r = montgomery_reduce(a);
			assert!(-Q < r && r < Q, "montgomery_reduce({a}) = {r} out of range");
			assert_eq!(((r as i128) << 32).rem_euclid(q), (a as i128).rem_euclid(q), "a = {a}");
		}
	}

	#[test]
	fn reduce32_congruence_and_range() {
		let max = i32::MAX - (1 << 22);
		let inputs = samples().map(|x| x as i32).filter(|&a| a <= max);
		for a in inputs.chain([i32::MIN, -Q, -1, 0, 1, Q, max]) {
			let r = reduce32(a);
			assert!((-6283008..=6283008).contains(&r), "reduce32({a}) = {r} out of range");
			assert_eq!(r.rem_euclid(Q), a.rem_euclid(Q), "a = {a}");
		}
	}

	#[test]
	fn caddq_maps_to_standard_representative() {
		let inputs = samples().map(|x| (x % (2 * Q as u64 - 1)) as i32 - (Q - 1));
		for a in inputs.chain([-(Q - 1), -1, 0, Q - 1]) {
			assert_eq!(caddq(a), a.rem_euclid(Q), "a = {a}");
		}
	}

	/// Security review: the domain `[-2^31*Q, 2^31*Q)` is half-open. At the
	/// excluded positive endpoint the signed low word truncates to
	/// `i32::MIN` (Q is odd), so the reduction returns exactly `Q` — the
	/// representative the `(-Q, Q)` output contract excludes. Everything
	/// inside the domain, including both extremes, stays strictly in range.
	#[test]
	fn montgomery_reduce_domain_endpoints() {
		let q = crate::params::Q as i64;
		let in_range = |r: i32| r > -crate::params::Q && r < crate::params::Q;

		// In-domain extremes: the negative (inclusive) endpoint and the
		// largest admitted input.
		assert!(in_range(super::montgomery_reduce(-(1i64 << 31) * q)));
		assert!(in_range(super::montgomery_reduce((1i64 << 31) * q - 1)));

		// The excluded endpoint yields exactly Q — this is *why* the domain
		// is half-open; callers must never pass it.
		assert_eq!(super::montgomery_reduce((1i64 << 31) * q), crate::params::Q);
	}
}
