use crate::{params, reduce::montgomery_reduce};

const N: usize = params::N as usize;

/// Powers of the root of unity in bit-reversed order, in Montgomery form (entry 0 is unused).
const ZETAS: [i32; N] = [
	0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468, 1826347, 2353451, -359251,
	-2091905, 3119733, -2884855, 3111497, 2680103, 2725464, 1024112, -1079900, 3585928, -549488,
	-1119584, 2619752, -2108549, -2118186, -3859737, -1399561, -3277672, 1757237, -19422, 4010497,
	280005, 2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439, -3861115,
	-3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299, -1699267, -1643818, 3505694,
	-3821735, 3507263, -2140649, -1600420, 3699596, 811944, 531354, 954230, 3881043, 3900724,
	-2556880, 2071892, -2797779, -3930395, -1528703, -3677745, -3041255, -1452451, 3475950,
	2176455, -1585221, -1257611, 1939314, -4083598, -1000202, -3190144, -3157330, -3632928, 126922,
	3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047, -671102, -1228525,
	-22981, -1308169, -381987, 1349076, 1852771, -1430430, -3343383, 264944, 508951, 3097992,
	44288, -1100098, 904516, 3958618, -3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969,
	-1316856, 189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330, 1285669,
	-1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961, 2091667, 3407706, 2316500,
	3817976, -3342478, 2244091, -2446433, -3562462, 266997, 2434439, -1235728, 3513181, -3520352,
	-3759364, -1197226, -3193378, 900702, 1859098, 909542, 819034, 495491, -1613174, -43260,
	-522500, -655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838, 342297,
	286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044, 2842341, 2691481, -2590150,
	1265009, 4055324, 1247620, 2486353, 1595974, -3767016, 1250494, 2635921, -3548272, -2994039,
	1869119, 1903435, -1050970, -1333058, 1237275, -3318210, -1430225, -451100, 1312455, 3306115,
	-1962642, -1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031, -542412,
	-2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993, -2013608, 2432395, 2454455,
	-164721, 1957272, 3369112, 185531, -1207385, -3183426, 162844, 1616392, 3014001, 810149,
	1652634, -3694233, -1799107, -3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735,
	472078, -426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893, -2939036,
	-2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687, -554416, 3919660, -48306,
	-1362209, 3937738, 1400424, -846154, 1976782,
];

/// `2^64 / N mod Q`: scales by `1/N` and leaves the Montgomery factor `2^32`.
const F: i64 = 41978;

/// Forward NTT, in-place. No modular reduction is performed after additions or subtractions. Output
/// vector is in bitreversed order.
#[inline(never)]
pub fn ntt(a: &mut [i32; N]) {
	let mut k = 0;
	let mut len = N / 2;
	while len > 0 {
		let mut start = 0;
		while start < N {
			k += 1;
			let zeta = ZETAS[k] as i64;
			for j in start..start + len {
				let t = montgomery_reduce(zeta * a[j + len] as i64);
				a[j + len] = a[j] - t;
				a[j] += t;
			}
			start += 2 * len;
		}
		len >>= 1;
	}
}

/// Inverse NTT and multiplication by Montgomery factor 2^32. In-place. No modular reductions after
/// additions or subtractions; input coefficients need to be smaller than Q in absolute value.
/// Output coefficient are smaller than Q in absolute value.
#[inline(never)]
pub fn invntt_tomont(a: &mut [i32; N]) {
	let mut k = N;
	let mut len = 1;
	while len < N {
		let mut start = 0;
		while start < N {
			k -= 1;
			let zeta = -ZETAS[k] as i64;
			let (lo, hi) = a[start..start + 2 * len].split_at_mut(len);
			for (x, y) in lo.iter_mut().zip(hi) {
				no_unroll_on_arm();
				let t = *x;
				*x = t + *y;
				*y = montgomery_reduce(zeta * (t - *y) as i64);
			}
			start += 2 * len;
		}
		// An opaque width keeps LLVM from unrolling the layers into one block that holds the
		// coefficients in registers across layers and spills them to stack slots nothing wipes.
		len = core::hint::black_box(len << 1);
	}
	for j in 0..N {
		no_unroll_on_arm();
		a[j] = montgomery_reduce(F * a[j] as i64);
	}
}

/// On 32-bit Arm, LLVM unrolls the butterfly and scaling loops and spills loaded coefficients to
/// stack slots nothing wipes. An empty barrier in the loop body stops that unrolling.
#[inline(always)]
fn no_unroll_on_arm() {
	#[cfg(target_arch = "arm")]
	core::hint::black_box(());
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::params::{Q, R};

	/// `ZETAS[k] = 2^32 * R^bitrev8(k) mod Q`, centered.
	#[test]
	fn zetas_are_montgomery_powers_of_the_root() {
		let q = Q as i64;
		for (k, &zeta) in ZETAS.iter().enumerate().skip(1) {
			let power = (0..(k as u8).reverse_bits()).fold(1i64, |acc, _| acc * R as i64 % q);
			assert!(zeta.abs() <= Q / 2, "ZETAS[{k}] is not centered");
			assert_eq!((montgomery_reduce(zeta as i64) as i64).rem_euclid(q), power, "ZETAS[{k}]");
		}
	}

	/// Multiplying through the NTT equals the schoolbook product modulo `X^N + 1` and Q.
	#[test]
	fn ntt_product_matches_schoolbook_negacyclic_product() {
		let q = Q as i64;
		let mut a: [i32; N] =
			core::array::from_fn(|i| ((i * i * 7919 + 13 * i + 5) % Q as usize) as i32);
		let mut b: [i32; N] =
			core::array::from_fn(|i| Q - 1 - ((i * 104729 + 271) % Q as usize) as i32);

		let mut expected = [0i64; N];
		for i in 0..N {
			for j in 0..N {
				let product = a[i] as i64 * b[j] as i64 % q;
				let sign = if i + j < N { 1 } else { -1 };
				let slot = &mut expected[(i + j) % N];
				*slot = (*slot + sign * product).rem_euclid(q);
			}
		}

		ntt(&mut a);
		ntt(&mut b);
		let mut c: [i32; N] =
			core::array::from_fn(|i| montgomery_reduce(a[i] as i64 * b[i] as i64));
		invntt_tomont(&mut c);

		for i in 0..N {
			assert!(c[i].abs() < Q, "coefficient {i} out of range");
			assert_eq!((c[i] as i64).rem_euclid(q), expected[i], "coefficient {i}");
		}
	}
}
