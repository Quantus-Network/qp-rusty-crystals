/-
  Shared ML-DSA constants and two's-complement wrapping, matching
  `dilithium/src/params.rs` and the `i32`/`i64` operations in `reduce.rs`.
-/

namespace MlDsaArith

/-- FIPS 204 `q = 2^{23} - 2^{13} + 1` (`params.rs`). -/
def Q : Int := 8380417

/-- Ring degree `n = 256`. -/
def N : Nat := 256

/-- Dropped bits `d = 13`. -/
def D : Nat := 13

/-- Primitive 512-th root of unity `ζ = 1753` (`params.rs` `R`). -/
def Zeta : Int := 1753

/-- `q^{-1} mod 2^{32}` (`reduce.rs` `Q_INV`). -/
def Q_INV : Int := 58728449

/-- `γ₂ = (q-1)/32` (ML-DSA-65/87). -/
def GAMMA2_32 : Int := (Q - 1) / 32

/-- `γ₂ = (q-1)/88` (ML-DSA-44). -/
def GAMMA2_88 : Int := (Q - 1) / 88

def W32 : Int := 2 ^ 32
def W64 : Int := 2 ^ 64
def I32MIN : Int := -(2 ^ 31)
def I32MAX : Int := 2 ^ 31 - 1

theorem Q_eq : Q = 2 ^ 23 - 2 ^ 13 + 1 := by decide
theorem Q_pos : (0 : Int) < Q := by decide
theorem Q_odd : Q % 2 = 1 := by decide
theorem GAMMA2_32_eq : GAMMA2_32 = 261888 := by decide
theorem GAMMA2_88_eq : GAMMA2_88 = 95232 := by decide
theorem W32_eq : W32 = 4294967296 := by decide
theorem I32MIN_eq : I32MIN = -2147483648 := by decide
theorem I32MAX_eq : I32MAX = 2147483647 := by decide
theorem two_pow_31 : (2 : Int) ^ 31 = 2147483648 := by decide
theorem two_pow_32 : (2 : Int) ^ 32 = 4294967296 := by decide
theorem two_pow_63 : (2 : Int) ^ 63 = 9223372036854775808 := by decide

/-- `Q_INV * Q ≡ 1 (mod 2^{32})`. -/
theorem Q_INV_spec : Q_INV * Q % W32 = 1 := by decide

/-- Two's-complement truncation to an `i32` representative in `[I32MIN, I32MAX]`. -/
def asI32 (a : Int) : Int :=
  let u := a % W32
  if 2 ^ 31 ≤ u then u - W32 else u

/-- Two's-complement truncation to an `i64`. -/
def asI64 (a : Int) : Int :=
  let u := a % W64
  if 2 ^ 63 ≤ u then u - W64 else u

def wrappingMul32 (a b : Int) : Int := asI32 (a * b)
def wrappingMul64 (a b : Int) : Int := asI64 (a * b)
def wrappingNeg32 (a : Int) : Int := asI32 (-a)

/-- Arithmetic right shift (Rust `>>` on signed integers): floor division by `2^k`. -/
def ashr (a : Int) (k : Nat) : Int := Int.fdiv a (2 ^ k)

/-- `a >> 31` on an `i32`: all-ones iff negative. -/
def signMask (a : Int) : Int := if a < 0 then -1 else 0

/-- Centered representative of `x` mod `Q`. -/
def centerQ (x : Int) : Int :=
  let r := x % Q
  if (Q - 1) / 2 < r then r - Q else r

/-- FIPS 204 `mod±_α`. -/
def modPM (m b : Int) : Int :=
  let m' := m % b
  if b / 2 < m' then m' - b else m'

end MlDsaArith
