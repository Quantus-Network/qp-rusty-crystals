// Port of Go's circl library NTT implementation to Rust
// This ensures compatibility with the Threshold-ML-DSA reference implementation

use qp_rusty_crystals_dilithium::params as dilithium_params;
use qp_rusty_crystals_dilithium::poly::Poly;

const N: usize = 256;
const Q: u32 = 8380417; // 2²³ - 2¹³ + 1
const QINV: u64 = 4236238847; // = -(q^-1) mod 2³²
const R_OVER_256: u64 = 41978; // = (256)⁻¹ R² mod q, where R=2³²

// Zetas lists precomputed powers of the root of unity in Montgomery
// representation used for the NTT
static ZETAS: [u32; N] = [
	4193792, 25847, 5771523, 7861508, 237124, 7602457, 7504169,
	466468, 1826347, 2353451, 8021166, 6288512, 3119733, 5495562,
	3111497, 2680103, 2725464, 1024112, 7300517, 3585928, 7830929,
	7260833, 2619752, 6271868, 6262231, 4520680, 6980856, 5102745,
	1757237, 8360995, 4010497, 280005, 2706023, 95776, 3077325,
	3530437, 6718724, 4788269, 5842901, 3915439, 4519302, 5336701,
	3574422, 5512770, 3539968, 8079950, 2348700, 7841118, 6681150,
	6736599, 3505694, 4558682, 3507263, 6239768, 6779997, 3699596,
	811944, 531354, 954230, 3881043, 3900724, 5823537, 2071892,
	5582638, 4450022, 6851714, 4702672, 5339162, 6927966, 3475950,
	2176455, 6795196, 7122806, 1939314, 4296819, 7380215, 5190273,
	5223087, 4747489, 126922, 3412210, 7396998, 2147896, 2715295,
	5412772, 4686924, 7969390, 5903370, 7709315, 7151892, 8357436,
	7072248, 7998430, 1349076, 1852771, 6949987, 5037034, 264944,
	508951, 3097992, 44288, 7280319, 904516, 3958618, 4656075,
	8371839, 1653064, 5130689, 2389356, 8169440, 759969, 7063561,
	189548, 4827145, 3159746, 6529015, 5971092, 8202977, 1315589,
	1341330, 1285669, 6795489, 7567685, 6940675, 5361315, 4499357,
	4751448, 3839961, 2091667, 3407706, 2316500, 3817976, 5037939,
	2244091, 5933984, 4817955, 266997, 2434439, 7144689, 3513181,
	4860065, 4621053, 7183191, 5187039, 900702, 1859098, 909542,
	819034, 495491, 6767243, 8337157, 7857917, 7725090, 5257975,
	2031748, 3207046, 4823422, 7855319, 7611795, 4784579, 342297,
	286988, 5942594, 4108315, 3437287, 5038140, 1735879, 203044,
	2842341, 2691481, 5790267, 1265009, 4055324, 1247620, 2486353,
	1595974, 4613401, 1250494, 2635921, 4832145, 5386378, 1869119,
	1903435, 7329447, 7047359, 1237275, 5062207, 6950192, 7929317,
	1312455, 3306115, 6417775, 7100756, 1917081, 5834105, 7005614,
	1500165, 777191, 2235880, 3406031, 7838005, 5548557, 6709241,
	6533464, 5796124, 4656147, 594136, 4603424, 6366809, 2432395,
	2454455, 8215696, 1957272, 3369112, 185531, 7173032, 5196991,
	162844, 1616392, 3014001, 810149, 1652634, 4686184, 6581310,
	5341501, 3523897, 3866901, 269760, 2213111, 7404533, 1717735,
	472078, 7953734, 1723600, 6577327, 1910376, 6712985, 7276084,
	8119771, 4546524, 5441381, 6144432, 7959518, 6094090, 183443,
	7403526, 1612842, 4834730, 7826001, 3919660, 8332111, 7018208,
	3937738, 1400424, 7534263, 1976782,
];

// InvZetas lists precomputed powers of the inverse root of unity in Montgomery
// representation used for the inverse NTT
static INV_ZETAS: [u32; N] = [
	6403635, 846154, 6979993, 4442679, 1362209, 48306, 4460757,
	554416, 3545687, 6767575, 976891, 8196974, 2286327, 420899,
	2235985, 2939036, 3833893, 260646, 1104333, 1667432, 6470041,
	1803090, 6656817, 426683, 7908339, 6662682, 975884, 6167306,
	8110657, 4513516, 4856520, 3038916, 1799107, 3694233, 6727783,
	7570268, 5366416, 6764025, 8217573, 3183426, 1207385, 8194886,
	5011305, 6423145, 164721, 5925962, 5948022, 2013608, 3776993,
	7786281, 3724270, 2584293, 1846953, 1671176, 2831860, 542412,
	4974386, 6144537, 7603226, 6880252, 1374803, 2546312, 6463336,
	1279661, 1962642, 5074302, 7067962, 451100, 1430225, 3318210,
	7143142, 1333058, 1050970, 6476982, 6511298, 2994039, 3548272,
	5744496, 7129923, 3767016, 6784443, 5894064, 7132797, 4325093,
	7115408, 2590150, 5688936, 5538076, 8177373, 6644538, 3342277,
	4943130, 4272102, 2437823, 8093429, 8038120, 3595838, 768622,
	525098, 3556995, 5173371, 6348669, 3122442, 655327, 522500,
	43260, 1613174, 7884926, 7561383, 7470875, 6521319, 7479715,
	3193378, 1197226, 3759364, 3520352, 4867236, 1235728, 5945978,
	8113420, 3562462, 2446433, 6136326, 3342478, 4562441, 6063917,
	4972711, 6288750, 4540456, 3628969, 3881060, 3019102, 1439742,
	812732, 1584928, 7094748, 7039087, 7064828, 177440, 2409325,
	1851402, 5220671, 3553272, 8190869, 1316856, 7620448, 210977,
	5991061, 3249728, 6727353, 8578, 3724342, 4421799, 7475901,
	1100098, 8336129, 5282425, 7871466, 8115473, 3343383, 1430430,
	6527646, 7031341, 381987, 1308169, 22981, 1228525, 671102,
	2477047, 411027, 3693493, 2967645, 5665122, 6232521, 983419,
	4968207, 8253495, 3632928, 3157330, 3190144, 1000202, 4083598,
	6441103, 1257611, 1585221, 6203962, 4904467, 1452451, 3041255,
	3677745, 1528703, 3930395, 2797779, 6308525, 2556880, 4479693,
	4499374, 7426187, 7849063, 7568473, 4680821, 1600420, 2140649,
	4873154, 3821735, 4874723, 1643818, 1699267, 539299, 6031717,
	300467, 4840449, 2867647, 4805995, 3043716, 3861115, 4464978,
	2537516, 3592148, 1661693, 4849980, 5303092, 8284641, 5674394,
	8100412, 4369920, 19422, 6623180, 3277672, 1399561, 3859737,
	2118186, 2108549, 5760665, 1119584, 549488, 4794489, 1079900,
	7356305, 5654953, 5700314, 5268920, 2884855, 5260684, 2091905,
	359251, 6026966, 6554070, 7913949, 876248, 777960, 8143293,
	518909, 2608894, 8354570, 4186625,
];

/// For x R ≤ q 2³², find y ≤ 2q with y = x mod q.
#[inline]
fn mont_reduce_le2q(x: u64) -> u32 {
	// Qinv = 4236238847 = -(q⁻¹) mod 2³²
	let m = (x.wrapping_mul(QINV)) & 0xffffffff;
	((x.wrapping_add(m.wrapping_mul(Q as u64))) >> 32) as u32
}

/// Pointwise multiplication of two polynomials in NTT domain (MulHat in Go)
/// This is Montgomery multiplication: p[i] = montReduceLe2Q(a[i] * b[i])
pub fn mul_hat(p: &mut Poly, a: &Poly, b: &Poly) {
	// Convert to u32 for computation
	let mut a_u32 = [0u32; N];
	let mut b_u32 = [0u32; N];

	for i in 0..N {
		a_u32[i] = if a.coeffs[i] < 0 {
			(a.coeffs[i] + Q as i32) as u32
		} else {
			a.coeffs[i] as u32
		};
		b_u32[i] = if b.coeffs[i] < 0 {
			(b.coeffs[i] + Q as i32) as u32
		} else {
			b.coeffs[i] as u32
		};
	}

	// Pointwise Montgomery multiplication
	for i in 0..N {
		let result = mont_reduce_le2q(a_u32[i] as u64 * b_u32[i] as u64);
		p.coeffs[i] = result as i32;
	}
}

/// Add two polynomials: p = a + b
pub fn poly_add(p: &mut Poly, a: &Poly, b: &Poly) {
	// Convert to u32 for wrapping addition
	let mut a_u32 = [0u32; N];
	let mut b_u32 = [0u32; N];

	for i in 0..N {
		a_u32[i] = if a.coeffs[i] < 0 {
			(a.coeffs[i] + Q as i32) as u32
		} else {
			a.coeffs[i] as u32
		};
		b_u32[i] = if b.coeffs[i] < 0 {
			(b.coeffs[i] + Q as i32) as u32
		} else {
			b.coeffs[i] as u32
		};
	}

	// Wrapping addition
	for i in 0..N {
		p.coeffs[i] = a_u32[i].wrapping_add(b_u32[i]) as i32;
	}
}

/// ReduceLe2Q reduces x to a value ≤ 2q
pub fn reduce_le2q(x: u32) -> u32 {
	// Note 2²³ = 2¹³ - 1 mod q. So, writing  x = x₁ 2²³ + x₂ with x₂ < 2²³
	// and x₁ < 2⁹, we have x = y (mod q) where
	// y = x₂ + x₁ 2¹³ - x₁ ≤ 2²³ + 2¹³ < 2q.
	let x1 = x >> 23;
	let x2 = x & 0x7FFFFF; // 2²³-1
	x2.wrapping_add(x1 << 13).wrapping_sub(x1)
}

/// Execute an in-place forward NTT on the polynomial.
///
/// Assumes the coefficients are in Montgomery representation and bounded
/// by 2*Q. The resulting coefficients are again in Montgomery representation,
/// but are only bounded by 18*Q.
///
/// This matches the Go circl library implementation exactly.
pub fn ntt(p: &mut Poly) {
	let coeffs = &mut p.coeffs;

	// Convert i32 coefficients to u32 for NTT computation
	let mut coeffs_u32 = [0u32; N];
	for i in 0..N {
		// Handle negative values by adding Q
		coeffs_u32[i] = if coeffs[i] < 0 {
			(coeffs[i] + Q as i32) as u32
		} else {
			coeffs[i] as u32
		};
	}

	let mut k = 0; // Index into Zetas

	// l runs over half the height of a row group (the number of butterflies in each row group)
	let mut l = N / 2;
	while l > 0 {
		// offset loops over the row groups in this column
		let mut offset = 0;
		while offset < N - l {
			k += 1;
			let zeta = ZETAS[k] as u64;

			// j loops over each butterfly in the row group
			for j in offset..(offset + l) {
				let t = mont_reduce_le2q(zeta * coeffs_u32[j + l] as u64);
				coeffs_u32[j + l] = coeffs_u32[j].wrapping_add(2 * Q).wrapping_sub(t); // Cooley--Tukey butterfly
				coeffs_u32[j] = coeffs_u32[j].wrapping_add(t);
			}

			offset += 2 * l;
		}
		l >>= 1;
	}

	// Convert back to i32
	for i in 0..N {
		coeffs[i] = coeffs_u32[i] as i32;
	}
}

/// Execute an in-place inverse NTT and multiply by Montgomery factor R
///
/// Assumes the coefficients are in Montgomery representation and bounded
/// by 2*Q. The resulting coefficients are again in Montgomery representation
/// and bounded by 2*Q.
///
/// This matches the Go circl library implementation exactly.
pub fn inv_ntt(p: &mut Poly) {
	let coeffs = &mut p.coeffs;

	// Convert i32 coefficients to u32 for NTT computation
	let mut coeffs_u32 = [0u32; N];
	for i in 0..N {
		// Handle negative values by adding Q
		coeffs_u32[i] = if coeffs[i] < 0 {
			(coeffs[i] + Q as i32) as u32
		} else {
			coeffs[i] as u32
		};
	}

	let mut k = 0; // Index into InvZetas

	// We basically do the opposite of NTT, but postpone dividing by 2 in the
	// inverse of the Cooley--Tukey butterfly and accumulate that to a big
	// division by 2⁸ at the end.

	let mut l = 1;
	while l < N {
		let mut offset = 0;
		while offset < N - l {
			let zeta = INV_ZETAS[k] as u64;
			k += 1;

			for j in offset..(offset + l) {
				let t = coeffs_u32[j]; // Gentleman--Sande butterfly
				coeffs_u32[j] = t.wrapping_add(coeffs_u32[j + l]);
				let t_updated = t.wrapping_add(256 * Q).wrapping_sub(coeffs_u32[j + l]);
				coeffs_u32[j + l] = mont_reduce_le2q(zeta * t_updated as u64);
			}

			offset += 2 * l;
		}
		l <<= 1;
	}

	// Final multiplication by R_OVER_256
	for j in 0..N {
		coeffs_u32[j] = mont_reduce_le2q(R_OVER_256 * coeffs_u32[j] as u64);
	}

	// Convert back to i32
	for i in 0..N {
		coeffs[i] = coeffs_u32[i] as i32;
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_ntt_basic() {
		let mut p = Poly::default();
		// Set up a simple test polynomial
		p.coeffs[0] = 1;
		p.coeffs[1] = 2;
		p.coeffs[2] = 3;

		ntt(&mut p);
		inv_ntt(&mut p);

		// After NTT and inverse NTT, should get back original (modulo some Montgomery factor)
		// This is a basic sanity check
	}

	#[test]
	fn test_mul_hat() {
		// Test pointwise multiplication in NTT domain
		let mut a = Poly::default();
		let mut b = Poly::default();
		let mut result = Poly::default();

		// Set up simple test values
		for i in 0..5 {
			a.coeffs[i] = (i + 1) as i32;
			b.coeffs[i] = (i + 2) as i32;
		}

		mul_hat(&mut result, &a, &b);

		// Basic sanity check - results should be non-zero
		assert_ne!(result.coeffs[0], 0);
	}

	#[test]
	fn test_ntt_matches_go_first_share() {
		// Test with the actual first share polynomial from Go debug output
		let mut p = Poly::default();

		// Full polynomial from Go: DEBUG GO: First share s1[0] FULL
		let go_coeffs = [
			8380416, 8380416, 8380417, 8380418, 8380416, 8380415, 8380418, 8380415, 8380417, 8380415, 8380416, 8380419, 8380416, 8380415, 8380415, 8380419,
			8380419, 8380417, 8380415, 8380416, 8380418, 8380418, 8380417, 8380418, 8380418, 8380418, 8380418, 8380415, 8380416, 8380417, 8380417, 8380417,
			8380416, 8380419, 8380416, 8380417, 8380417, 8380417, 8380416, 8380419, 8380415, 8380415, 8380416, 8380415, 8380418, 8380417, 8380415, 8380418,
			8380418, 8380418, 8380419, 8380416, 8380416, 8380419, 8380416, 8380415, 8380418, 8380417, 8380416, 8380415, 8380415, 8380415, 8380417, 8380417,
			8380416, 8380417, 8380415, 8380416, 8380417, 8380417, 8380419, 8380417, 8380419, 8380417, 8380417, 8380419, 8380418, 8380416, 8380418, 8380419,
			8380416, 8380418, 8380418, 8380417, 8380419, 8380418, 8380417, 8380415, 8380415, 8380418, 8380418, 8380415, 8380417, 8380415, 8380417, 8380417,
			8380418, 8380418, 8380415, 8380419, 8380416, 8380415, 8380416, 8380418, 8380417, 8380416, 8380418, 8380418, 8380416, 8380416, 8380415, 8380417,
			8380417, 8380415, 8380418, 8380416, 8380417, 8380416, 8380418, 8380416, 8380416, 8380417, 8380416, 8380419, 8380419, 8380418, 8380417, 8380415,
			8380419, 8380416, 8380415, 8380417, 8380418, 8380418, 8380419, 8380418, 8380415, 8380418, 8380415, 8380419, 8380417, 8380418, 8380419, 8380416,
			8380416, 8380419, 8380419, 8380415, 8380415, 8380419, 8380417, 8380417, 8380417, 8380418, 8380419, 8380417, 8380419, 8380418, 8380415, 8380419,
			8380416, 8380415, 8380415, 8380415, 8380418, 8380419, 8380417, 8380415, 8380417, 8380418, 8380415, 8380416, 8380419, 8380417, 8380416, 8380419,
			8380416, 8380415, 8380415, 8380417, 8380418, 8380415, 8380415, 8380419, 8380415, 8380415, 8380419, 8380415, 8380417, 8380417, 8380417, 8380418,
			8380416, 8380417, 8380417, 8380418, 8380419, 8380417, 8380416, 8380418, 8380418, 8380419, 8380415, 8380417, 8380418, 8380416, 8380416, 8380419,
			8380419, 8380416, 8380416, 8380417, 8380415, 8380418, 8380416, 8380417, 8380418, 8380415, 8380419, 8380416, 8380419, 8380415, 8380418, 8380415,
			8380419, 8380418, 8380418, 8380417, 8380418, 8380418, 8380418, 8380417, 8380417, 8380419, 8380419, 8380416, 8380419, 8380415, 8380419, 8380417,
			8380415, 8380418, 8380418, 8380416, 8380419, 8380415, 8380416, 8380418, 8380419, 8380417, 8380416, 8380415, 8380417, 8380417, 8380416, 8380415,
		];

		for i in 0..256 {
			p.coeffs[i] = go_coeffs[i] as i32;
		}

		eprintln!("Input coeffs[0..5]: {:?}", &p.coeffs[0..5]);

		ntt(&mut p);

		eprintln!("Output coeffs[0..5]: {:?}", &p.coeffs[0..5]);
		eprintln!("Expected: [34915453, 37803751, 41654889, 51878135, 44099773]");

		// Expected output from Go: [34915453 37803751 41654889 51878135 44099773]
		assert_eq!(p.coeffs[0], 34915453, "coeff[0] mismatch");
		assert_eq!(p.coeffs[1], 37803751, "coeff[1] mismatch");
		assert_eq!(p.coeffs[2], 41654889, "coeff[2] mismatch");
		assert_eq!(p.coeffs[3], 51878135, "coeff[3] mismatch");
		assert_eq!(p.coeffs[4], 44099773, "coeff[4] mismatch");
	}
}
