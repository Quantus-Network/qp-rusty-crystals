//! Challenge instances: the ML-DSA key-recovery lattice without a planted key.
//!
//! An instance is `(A, b)` with `A` an `m × n` integer matrix cut from the
//! negacyclic expansion of ML-DSA's `ExpandA(rho)` and `b` an `m`-vector in
//! the public-key encoding `t1 · 2^D`. The lattice is
//!
//! ```text
//! L = { (x, y, w) ∈ Z^n × Z^m × Z : y ≡ x·Aᵀ + w·b (mod q) }
//! ```
//!
//! For a real public key, `(s1, t0 − s2, −1)` is an unusually short vector of
//! `L`. For a Fiat–Shamir instance `b` is uniform, so no such vector is known
//! to exist and the task is pure basis reduction.

use core::fmt;
use std::str::FromStr;

use qp_rusty_crystals_dilithium::{
	fips202, ml_dsa_44, ml_dsa_65, ml_dsa_87, packing, params,
	poly::{self, Poly},
	polyvec::Polyvec,
};
use serde::{Deserialize, Serialize};

use crate::basis::Basis;

/// ML-DSA modulus.
pub const Q: i64 = params::Q as i64;
/// Ring dimension (degree of `x^N + 1`).
pub const RING_DIM: usize = params::N as usize;
/// Bits dropped from `t` in the public key (`t = t1·2^D + t0`).
pub const DROPPED_BITS: u32 = params::D as u32;
/// Bit width of each `t1` coefficient in the public key.
const T1_BITS: u32 = 10;

const RHO_DOMAIN: &[u8] = b"qp-lattice-attack/rho/v1";
const T1_DOMAIN: &[u8] = b"qp-lattice-attack/t1/v1";
const ID_DOMAIN: &[u8] = b"qp-lattice-attack/id/v1";

/// FIPS 204 parameter set. Fixes `q`, the ring dimension and the `k × l`
/// shape of `A`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Variant {
	MlDsa44,
	MlDsa65,
	MlDsa87,
}

impl Variant {
	pub const ALL: [Variant; 3] = [Variant::MlDsa44, Variant::MlDsa65, Variant::MlDsa87];

	/// Rows of `A` (polynomials).
	pub fn k(self) -> usize {
		match self {
			Variant::MlDsa44 => params::ml_dsa_44::K,
			Variant::MlDsa65 => params::ml_dsa_65::K,
			Variant::MlDsa87 => params::ml_dsa_87::K,
		}
	}

	/// Columns of `A` (polynomials).
	pub fn l(self) -> usize {
		match self {
			Variant::MlDsa44 => params::ml_dsa_44::L,
			Variant::MlDsa65 => params::ml_dsa_65::L,
			Variant::MlDsa87 => params::ml_dsa_87::L,
		}
	}

	/// Secret-key coefficient bound η.
	pub fn eta(self) -> i64 {
		match self {
			Variant::MlDsa44 => params::ml_dsa_44::ETA as i64,
			Variant::MlDsa65 => params::ml_dsa_65::ETA as i64,
			Variant::MlDsa87 => params::ml_dsa_87::ETA as i64,
		}
	}

	/// Largest `n` (integer columns of `A`) for this variant.
	pub fn max_n(self) -> usize {
		self.l() * RING_DIM
	}

	/// Largest `m` (integer rows of `A`) for this variant.
	pub fn max_m(self) -> usize {
		self.k() * RING_DIM
	}

	pub fn public_key_bytes(self) -> usize {
		match self {
			Variant::MlDsa44 => ml_dsa_44::PUBLICKEYBYTES,
			Variant::MlDsa65 => ml_dsa_65::PUBLICKEYBYTES,
			Variant::MlDsa87 => ml_dsa_87::PUBLICKEYBYTES,
		}
	}

	fn tag(self) -> u8 {
		match self {
			Variant::MlDsa44 => 44,
			Variant::MlDsa65 => 65,
			Variant::MlDsa87 => 87,
		}
	}
}

impl fmt::Display for Variant {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "ML-DSA-{}", self.tag())
	}
}

impl FromStr for Variant {
	type Err = InstanceError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s.trim().to_ascii_lowercase().as_str() {
			"44" | "ml-dsa-44" | "mldsa44" => Ok(Variant::MlDsa44),
			"65" | "ml-dsa-65" | "mldsa65" => Ok(Variant::MlDsa65),
			"87" | "ml-dsa-87" | "mldsa87" => Ok(Variant::MlDsa87),
			_ => Err(InstanceError::UnknownVariant),
		}
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstanceError {
	UnknownVariant,
	/// `n` or `m` is zero or exceeds the variant's matrix size.
	BadDimensions {
		n: usize,
		m: usize,
		max_n: usize,
		max_m: usize,
	},
	/// Public key length does not match the variant.
	BadPublicKeyLength {
		expected: usize,
		actual: usize,
	},
}

impl fmt::Display for InstanceError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			InstanceError::UnknownVariant => write!(f, "unknown ML-DSA variant"),
			InstanceError::BadDimensions { n, m, max_n, max_m } => write!(
				f,
				"instance dimensions n={n}, m={m} out of range (1..={max_n}, 1..={max_m})"
			),
			InstanceError::BadPublicKeyLength { expected, actual } =>
				write!(f, "public key has {actual} bytes, expected {expected}"),
		}
	}
}

impl std::error::Error for InstanceError {}

/// Serializable identity of an instance, enough to regenerate it (for seeded
/// instances) and to recognise it (for all instances).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceDescriptor {
	/// Hex of the content hash over `(variant, n, m, rho, b)`.
	pub id: String,
	pub variant: Variant,
	/// Hex seed for Fiat–Shamir instances; absent for imported public keys.
	pub seed: Option<String>,
	pub n: usize,
	pub m: usize,
	/// Lattice dimension `n + m + 1`.
	pub dim: usize,
}

/// A challenge lattice `(A, b)` together with its provenance.
#[derive(Clone, Debug)]
pub struct Instance {
	variant: Variant,
	seed: Option<[u8; 32]>,
	rho: [u8; params::SEEDBYTES],
	n: usize,
	m: usize,
	/// `m` rows of `n` entries in `[0, q)`.
	a: Vec<Vec<i64>>,
	/// `m` entries in `[0, q)`.
	b: Vec<i64>,
	id: [u8; 32],
}

impl Instance {
	/// Fiat–Shamir instance: `rho` and `t1` are both derived from `seed`, so
	/// nobody knows a short vector.
	pub fn generate(
		variant: Variant,
		seed: [u8; 32],
		n: usize,
		m: usize,
	) -> Result<Self, InstanceError> {
		check_dims(variant, n, m)?;

		let mut rho = [0u8; params::SEEDBYTES];
		let mut input = Vec::with_capacity(RHO_DOMAIN.len() + 1 + seed.len());
		input.extend_from_slice(RHO_DOMAIN);
		input.push(variant.tag());
		input.extend_from_slice(&seed);
		fips202::shake256(&mut rho, &input);

		let mut t1_input = Vec::with_capacity(T1_DOMAIN.len() + 1 + seed.len());
		t1_input.extend_from_slice(T1_DOMAIN);
		t1_input.push(variant.tag());
		t1_input.extend_from_slice(&seed);
		// Sample the whole `t1` so that an instance with fewer rows is a
		// prefix of the full one.
		let mut stream = vec![0u8; 2 * variant.max_m()];
		fips202::shake256(&mut stream, &t1_input);
		let b = stream
			.chunks_exact(2)
			.take(m)
			.map(|c| {
				((u16::from_le_bytes([c[0], c[1]]) & ((1 << T1_BITS) - 1)) as i64) << DROPPED_BITS
			})
			.collect();

		Ok(Self::assemble(variant, Some(seed), rho, n, m, b))
	}

	/// Full-dimension Fiat–Shamir instance (`n = 256·l`, `m = 256·k`).
	pub fn full(variant: Variant, seed: [u8; 32]) -> Self {
		Self::generate(variant, seed, variant.max_n(), variant.max_m())
			.expect("full dimensions are always valid")
	}

	/// The key-recovery lattice of a real ML-DSA public key, restricted to
	/// the first `n` secret coordinates and `m` equations.
	pub fn from_public_key(
		variant: Variant,
		pk: &[u8],
		n: usize,
		m: usize,
	) -> Result<Self, InstanceError> {
		check_dims(variant, n, m)?;
		if pk.len() != variant.public_key_bytes() {
			return Err(InstanceError::BadPublicKeyLength {
				expected: variant.public_key_bytes(),
				actual: pk.len(),
			});
		}
		let (rho, t1) = match variant {
			Variant::MlDsa44 =>
				unpack_t1::<{ params::ml_dsa_44::K }, { ml_dsa_44::PUBLICKEYBYTES }>(pk),
			Variant::MlDsa65 =>
				unpack_t1::<{ params::ml_dsa_65::K }, { ml_dsa_65::PUBLICKEYBYTES }>(pk),
			Variant::MlDsa87 =>
				unpack_t1::<{ params::ml_dsa_87::K }, { ml_dsa_87::PUBLICKEYBYTES }>(pk),
		};
		let b = t1.into_iter().take(m).map(|c| c << DROPPED_BITS).collect();
		Ok(Self::assemble(variant, None, rho, n, m, b))
	}

	fn assemble(
		variant: Variant,
		seed: Option<[u8; 32]>,
		rho: [u8; params::SEEDBYTES],
		n: usize,
		m: usize,
		b: Vec<i64>,
	) -> Self {
		let a = expand_submatrix(&rho, n, m);

		let mut id_input = Vec::with_capacity(ID_DOMAIN.len() + 1 + 16 + rho.len() + 8 * m);
		id_input.extend_from_slice(ID_DOMAIN);
		id_input.push(variant.tag());
		id_input.extend_from_slice(&(n as u64).to_le_bytes());
		id_input.extend_from_slice(&(m as u64).to_le_bytes());
		id_input.extend_from_slice(&rho);
		for &x in &b {
			id_input.extend_from_slice(&x.to_le_bytes());
		}
		let mut id = [0u8; 32];
		fips202::shake256(&mut id, &id_input);

		Instance { variant, seed, rho, n, m, a, b, id }
	}

	pub fn variant(&self) -> Variant {
		self.variant
	}

	/// Secret coordinates used (columns of `A`).
	pub fn n(&self) -> usize {
		self.n
	}

	/// Equations used (rows of `A`).
	pub fn m(&self) -> usize {
		self.m
	}

	/// Lattice dimension `n + m + 1`.
	pub fn dim(&self) -> usize {
		self.n + self.m + 1
	}

	pub fn seed(&self) -> Option<&[u8; 32]> {
		self.seed.as_ref()
	}

	pub fn rho(&self) -> &[u8; params::SEEDBYTES] {
		&self.rho
	}

	/// Content hash identifying the instance.
	pub fn id(&self) -> &[u8; 32] {
		&self.id
	}

	pub fn id_hex(&self) -> String {
		hex(&self.id)
	}

	/// Row `j` of `A` (`n` entries in `[0, q)`).
	pub fn a_row(&self, j: usize) -> &[i64] {
		&self.a[j]
	}

	/// Target vector `b` (`m` entries in `[0, q)`).
	pub fn b(&self) -> &[i64] {
		&self.b
	}

	pub fn descriptor(&self) -> InstanceDescriptor {
		InstanceDescriptor {
			id: self.id_hex(),
			variant: self.variant,
			seed: self.seed.as_ref().map(|s| hex(s)),
			n: self.n,
			m: self.m,
			dim: self.dim(),
		}
	}

	/// Canonical starting basis, rows ordered `q`-rows, identity/`Aᵀ` rows,
	/// then the `b` row. Its Gram–Schmidt profile is `q` (m times) followed by
	/// `1` (n + 1 times).
	pub fn start_basis(&self) -> Basis {
		let d = self.dim();
		let mut rows = Vec::with_capacity(d);
		for j in 0..self.m {
			let mut r = vec![0i64; d];
			r[self.n + j] = Q;
			rows.push(r);
		}
		for i in 0..self.n {
			let mut r = vec![0i64; d];
			r[i] = 1;
			for j in 0..self.m {
				r[self.n + j] = self.a[j][i];
			}
			rows.push(r);
		}
		let mut r = vec![0i64; d];
		r[self.n..self.n + self.m].copy_from_slice(&self.b);
		r[d - 1] = 1;
		rows.push(r);
		Basis::new(rows)
	}

	/// Log-potential `Σ_{i} (d − 1 − i) ln ‖b*_i‖` of [`Self::start_basis`],
	/// in nats, from its closed-form profile.
	pub fn start_potential(&self) -> f64 {
		let d = self.dim() as f64;
		let m = self.m as f64;
		(Q as f64).ln() * (m * (d - 1.0) - m * (m - 1.0) / 2.0)
	}

	/// Natural log of the lattice volume, `m · ln q`.
	pub fn log_volume(&self) -> f64 {
		self.m as f64 * (Q as f64).ln()
	}

	/// Exact membership test for one row `(x, y, w)` of length `dim()`.
	///
	/// Entries must be below `2^62` in magnitude for the `i128` accumulation
	/// to be exact; the verifier enforces a far tighter bound before calling.
	pub fn contains(&self, row: &[i64]) -> bool {
		if row.len() != self.dim() {
			return false;
		}
		let (x, rest) = row.split_at(self.n);
		let (y, w) = rest.split_at(self.m);
		let w = w[0] as i128;
		let q = Q as i128;
		for ((a_row, &b_j), &y_j) in self.a.iter().zip(&self.b).zip(y) {
			let mut acc: i128 = w * b_j as i128 - y_j as i128;
			for (xi, aji) in x.iter().zip(a_row) {
				acc += (*xi as i128) * (*aji as i128);
			}
			if acc.rem_euclid(q) != 0 {
				return false;
			}
		}
		true
	}
}

fn check_dims(variant: Variant, n: usize, m: usize) -> Result<(), InstanceError> {
	let (max_n, max_m) = (variant.max_n(), variant.max_m());
	if n == 0 || m == 0 || n > max_n || m > max_m {
		return Err(InstanceError::BadDimensions { n, m, max_n, max_m });
	}
	Ok(())
}

fn unpack_t1<const K: usize, const PK: usize>(pk: &[u8]) -> ([u8; params::SEEDBYTES], Vec<i64>) {
	let pk: &[u8; PK] = pk.try_into().expect("length checked by caller");
	let mut rho = [0u8; params::SEEDBYTES];
	let mut t1 = Polyvec::<K>::default();
	packing::unpack_pk::<K, PK>(&mut rho, &mut t1, pk);
	let flat = t1.vec.iter().flat_map(|p| p.coeffs().iter().map(|&c| c as i64)).collect();
	(rho, flat)
}

/// `2^-32 mod q`: `invntt_tomont` returns the inverse NTT scaled by `2^32`.
const MONT_R_INV: i64 = mod_inverse((1u64 << 32) % Q as u64) as i64;

const fn mod_pow(mut base: u64, mut exp: u64) -> u64 {
	let q = Q as u64;
	let mut acc = 1u64;
	base %= q;
	while exp > 0 {
		if exp & 1 == 1 {
			acc = acc * base % q;
		}
		base = base * base % q;
		exp >>= 1;
	}
	acc
}

const fn mod_inverse(x: u64) -> u64 {
	mod_pow(x, Q as u64 - 2)
}

/// Coefficient-domain polynomial `A[i][j]` with coefficients in `[0, q)`.
///
/// `ExpandA` samples the matrix directly in the NTT domain (FIPS 204), so the
/// integer matrix an attacker works with is the inverse NTT of what
/// `poly::uniform` produces.
fn coefficient_poly(rho: &[u8; params::SEEDBYTES], i: usize, j: usize) -> [i64; RING_DIM] {
	let mut p = Poly::default();
	poly::uniform(&mut p, rho, ((i << 8) + j) as u16);
	poly::invntt_tomont(&mut p);
	let mut out = [0i64; RING_DIM];
	for (o, &c) in out.iter_mut().zip(p.coeffs()) {
		*o = (c as i64 * MONT_R_INV).rem_euclid(Q);
	}
	out
}

/// First `m` rows and `n` columns of the negacyclic integer expansion of `A`.
///
/// Multiplying polynomial `a` by `s` in `Z_q[x]/(x^N + 1)` gives coefficient
/// `r` of the product as `Σ_{c ≤ r} a_{r−c} s_c − Σ_{c > r} a_{N+r−c} s_c`.
fn expand_submatrix(rho: &[u8; params::SEEDBYTES], n: usize, m: usize) -> Vec<Vec<i64>> {
	let poly_rows = m.div_ceil(RING_DIM);
	let poly_cols = n.div_ceil(RING_DIM);
	let mut polys = Vec::with_capacity(poly_rows * poly_cols);
	for i in 0..poly_rows {
		for j in 0..poly_cols {
			polys.push(coefficient_poly(rho, i, j));
		}
	}

	let mut a = vec![vec![0i64; n]; m];
	for (row_idx, row) in a.iter_mut().enumerate() {
		let (i, r) = (row_idx / RING_DIM, row_idx % RING_DIM);
		for (col_idx, entry) in row.iter_mut().enumerate() {
			let (j, c) = (col_idx / RING_DIM, col_idx % RING_DIM);
			let p = &polys[i * poly_cols + j];
			*entry = if r >= c { p[r - c] } else { (Q - p[RING_DIM + r - c]) % Q };
		}
	}
	a
}

pub(crate) fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
	use qp_rusty_crystals_dilithium::{ml_dsa_44, ml_dsa_65, ml_dsa_87, params, SensitiveBytes32};

	use super::*;

	fn seed(byte: u8) -> [u8; 32] {
		[byte; 32]
	}

	#[test]
	fn montgomery_constant_is_inverse_of_2_pow_32() {
		let r = ((1u64 << 32) % Q as u64) as i64;
		assert_eq!((r * MONT_R_INV).rem_euclid(Q), 1);
	}

	#[test]
	fn generation_is_deterministic_and_seed_sensitive() {
		let a = Instance::generate(Variant::MlDsa44, seed(1), 20, 20).unwrap();
		let b = Instance::generate(Variant::MlDsa44, seed(1), 20, 20).unwrap();
		let c = Instance::generate(Variant::MlDsa44, seed(2), 20, 20).unwrap();
		assert_eq!(a.id(), b.id());
		assert_eq!(a.start_basis(), b.start_basis());
		assert_ne!(a.id(), c.id());
		assert_ne!(a.b(), c.b());
		assert_ne!(a.a_row(0), c.a_row(0));
		assert_eq!(a.dim(), 41);
	}

	#[test]
	fn smaller_instances_are_prefixes_of_larger_ones() {
		let small = Instance::generate(Variant::MlDsa65, seed(7), 300, 270).unwrap();
		let large = Instance::generate(Variant::MlDsa65, seed(7), 600, 520).unwrap();
		assert_eq!(small.rho(), large.rho());
		assert_eq!(small.b(), &large.b()[..270]);
		for j in 0..270 {
			assert_eq!(small.a_row(j), &large.a_row(j)[..300]);
		}
		assert_ne!(small.id(), large.id());
	}

	#[test]
	fn dimensions_are_validated() {
		assert!(Instance::generate(Variant::MlDsa44, seed(0), 0, 5).is_err());
		assert!(Instance::generate(Variant::MlDsa44, seed(0), 5, 0).is_err());
		assert!(Instance::generate(Variant::MlDsa44, seed(0), 1025, 5).is_err());
		assert!(Instance::generate(Variant::MlDsa44, seed(0), 5, 1025).is_err());
		assert!(Instance::generate(Variant::MlDsa44, seed(0), 1024, 1024).is_ok());
		assert!(Instance::from_public_key(Variant::MlDsa44, &[0u8; 10], 5, 5).is_err());
	}

	#[test]
	fn start_basis_rows_lie_in_the_lattice() {
		let inst = Instance::generate(Variant::MlDsa87, seed(3), 37, 29).unwrap();
		let basis = inst.start_basis();
		assert!(basis.is_square());
		assert_eq!(basis.len(), inst.dim());
		for row in &basis.rows {
			assert!(inst.contains(row));
		}
		let mut bad = basis.rows[inst.m()].clone();
		bad[inst.n()] += 1;
		assert!(!inst.contains(&bad));
		assert!(!inst.contains(&basis.rows[0][..inst.dim() - 1]));
	}

	#[test]
	fn start_potential_matches_closed_form_shape() {
		let inst = Instance::generate(Variant::MlDsa44, seed(9), 10, 4).unwrap();
		// d = 15; weights for the four q-rows are 14, 13, 12, 11.
		let expected = (Q as f64).ln() * (14.0 + 13.0 + 12.0 + 11.0);
		assert!((inst.start_potential() - expected).abs() < 1e-9);
		assert!((inst.log_volume() - 4.0 * (Q as f64).ln()).abs() < 1e-12);
	}

	#[test]
	fn variant_parsing_and_display() {
		assert_eq!("ml-dsa-65".parse::<Variant>().unwrap(), Variant::MlDsa65);
		assert_eq!("87".parse::<Variant>().unwrap(), Variant::MlDsa87);
		assert!("99".parse::<Variant>().is_err());
		assert_eq!(Variant::MlDsa44.to_string(), "ML-DSA-44");
		let d = Instance::generate(Variant::MlDsa44, seed(1), 3, 2).unwrap().descriptor();
		assert_eq!(d.seed.as_deref(), Some("01".repeat(32).as_str()));
		assert_eq!(d.dim, 6);
	}

	/// The vector `(s1, t0 − s2, −1)` of a real key must lie in the lattice
	/// built from its public key. This pins down the NTT-domain convention of
	/// `ExpandA`, the Montgomery scaling, the negacyclic sign pattern and the
	/// `t1 · 2^D` encoding all at once.
	fn check_real_key<const K: usize, const L: usize, const ETA: usize, const SK: usize>(
		variant: Variant,
		sk: &[u8; SK],
		pk: &[u8],
		m: usize,
	) {
		let mut rho = [0u8; params::SEEDBYTES];
		let mut tr = [0u8; params::TR_BYTES];
		let mut key = [0u8; params::SEEDBYTES];
		let mut t0 = Polyvec::<K>::default();
		let mut s1 = Polyvec::<L>::default();
		let mut s2 = Polyvec::<K>::default();
		assert!(packing::unpack_sk::<K, L, ETA, SK>(
			&mut rho, &mut tr, &mut key, &mut t0, &mut s1, &mut s2, sk
		));

		let n = variant.max_n();
		let inst = Instance::from_public_key(variant, pk, n, m).unwrap();
		assert_eq!(inst.rho(), &rho);

		let mut v = Vec::with_capacity(inst.dim());
		for p in &s1.vec {
			v.extend(p.coeffs().iter().map(|&c| c as i64));
		}
		for (p0, p2) in t0.vec.iter().zip(&s2.vec) {
			v.extend(p0.coeffs().iter().zip(p2.coeffs()).map(|(&a, &b)| a as i64 - b as i64));
		}
		v.truncate(n + m);
		v.push(-1);
		assert_eq!(v.len(), inst.dim());
		assert!(inst.contains(&v), "{variant}: secret vector not in lattice");

		let mut wrong = v.clone();
		wrong[0] += 1;
		assert!(!inst.contains(&wrong));

		// One row from each block of the start basis; the full check is slow
		// in debug builds at these sizes and is covered on small instances.
		let basis = inst.start_basis();
		for idx in [0, m, m + n] {
			assert!(inst.contains(&basis.rows[idx]));
		}
	}

	#[test]
	fn real_key_secret_lies_in_lattice_ml_dsa_44() {
		let mut entropy = [0x11u8; 32];
		let kp = ml_dsa_44::Keypair::generate(&mut SensitiveBytes32::new(&mut entropy));
		let sk = kp.secret().to_bytes();
		let pk = kp.public().to_bytes();
		check_real_key::<
			{ params::ml_dsa_44::K },
			{ params::ml_dsa_44::L },
			{ params::ml_dsa_44::ETA },
			{ ml_dsa_44::SECRETKEYBYTES },
		>(Variant::MlDsa44, &sk, &pk, Variant::MlDsa44.max_m());
		check_real_key::<
			{ params::ml_dsa_44::K },
			{ params::ml_dsa_44::L },
			{ params::ml_dsa_44::ETA },
			{ ml_dsa_44::SECRETKEYBYTES },
		>(Variant::MlDsa44, &sk, &pk, 300);
	}

	#[test]
	fn real_key_secret_lies_in_lattice_ml_dsa_65() {
		let mut entropy = [0x22u8; 32];
		let kp = ml_dsa_65::Keypair::generate(&mut SensitiveBytes32::new(&mut entropy));
		let sk = kp.secret().to_bytes();
		let pk = kp.public().to_bytes();
		check_real_key::<
			{ params::ml_dsa_65::K },
			{ params::ml_dsa_65::L },
			{ params::ml_dsa_65::ETA },
			{ ml_dsa_65::SECRETKEYBYTES },
		>(Variant::MlDsa65, &sk, &pk, Variant::MlDsa65.max_m());
	}

	#[test]
	fn real_key_secret_lies_in_lattice_ml_dsa_87() {
		let mut entropy = [0x33u8; 32];
		let kp = ml_dsa_87::Keypair::generate(&mut SensitiveBytes32::new(&mut entropy));
		let sk = kp.secret().to_bytes();
		let pk = kp.public().to_bytes();
		check_real_key::<
			{ params::ml_dsa_87::K },
			{ params::ml_dsa_87::L },
			{ params::ml_dsa_87::ETA },
			{ ml_dsa_87::SECRETKEYBYTES },
		>(Variant::MlDsa87, &sk, &pk, Variant::MlDsa87.max_m());
	}
}
