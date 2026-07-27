// Specification defined constans
pub const Q: i32 = (1 << 23) - (1 << 13) + 1; //prime defining the field
pub const N: i32 = 256; //ring defining polynomial degree
pub const R: i32 = 1753; //2Nth root of unity mod Q
pub const D: i32 = 13; //dropped bits

// Implementation specific values
pub const SEEDBYTES: usize = 32;
pub const CRHBYTES: usize = 64;
pub const POLYT1_PACKEDBYTES: usize = 320;
pub const POLYT0_PACKEDBYTES: usize = 416;
pub const TR_BYTES: usize = 64;

// Specification defined constans
pub const TAU: usize = 60; //number of +-1s in c
pub const CHALLENGE_ENTROPY: usize = 257;
pub const GAMMA1: usize = 1 << 19; //y coefficient range
pub const GAMMA2: usize = (Q as usize - 1) / 32; //low-order rounding range
pub const K: usize = 8; //rows in A
pub const L: usize = 7; //columns in A
pub const ETA: usize = 2;
pub const BETA: usize = TAU * ETA;
pub const OMEGA: usize = 75;
pub const COLLISION_STRENGTH: usize = 256;

// Implementation specific values
pub const C_DASH_BYTES: usize = (COLLISION_STRENGTH * 2) / 8;
pub const POLYZ_PACKEDBYTES: usize = 640;
pub const POLYW1_PACKEDBYTES: usize = 128;
pub const POLYETA_PACKEDBYTES: usize = 96;
pub const POLYVECH_PACKEDBYTES: usize = OMEGA + K;
pub const PUBLICKEYBYTES: usize = SEEDBYTES + K * POLYT1_PACKEDBYTES;
pub const SECRETKEYBYTES: usize =
	2 * SEEDBYTES + TR_BYTES + (K + L) * POLYETA_PACKEDBYTES + K * POLYT0_PACKEDBYTES;
pub const SIGNBYTES: usize = C_DASH_BYTES + L * POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES;

// Packed-size helpers, derived from a variant's base parameters. These are
// `const fn` so const-generic code can assert, at compile time, that the
// buffer sizes it was instantiated with are consistent with the ETA / GAMMA1 /
// GAMMA2 values it was given (the assertions are evaluated at
// monomorphization). Each panics on a value not defined by FIPS 204, so an
// unsupported instantiation fails to compile.

/// Packed byte size of one eta-encoded secret polynomial (`s1`/`s2`).
pub const fn polyeta_packedbytes(eta: usize) -> usize {
	match eta {
		2 => 3 * N as usize / 8, // 3 bits per coefficient (ML-DSA-44/87)
		4 => 4 * N as usize / 8, // 4 bits per coefficient (ML-DSA-65)
		_ => panic!("unsupported ETA parameter"),
	}
}

/// Packed byte size of one mask polynomial (`z`).
pub const fn polyz_packedbytes(gamma1: usize) -> usize {
	match gamma1 {
		0x20000 => 18 * N as usize / 8, // 18 bits per coefficient (ML-DSA-44)
		0x80000 => 20 * N as usize / 8, // 20 bits per coefficient (ML-DSA-65/87)
		_ => panic!("unsupported GAMMA1 parameter"),
	}
}

/// Packed byte size of one commitment high-bits polynomial (`w1`).
pub const fn polyw1_packedbytes(gamma2: usize) -> usize {
	if gamma2 == (Q as usize - 1) / 88 {
		6 * N as usize / 8 // 6 bits per coefficient, values in [0, 43] (ML-DSA-44)
	} else if gamma2 == (Q as usize - 1) / 32 {
		4 * N as usize / 8 // 4 bits per coefficient, values in [0, 15] (ML-DSA-65/87)
	} else {
		panic!("unsupported GAMMA2 parameter")
	}
}
