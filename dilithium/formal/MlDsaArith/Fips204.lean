import MlDsaArith.Params

namespace MlDsaArith

/-! Independent transcription of FIPS 204 Algs 35–42 (and BitRev8).
Not copied from Apple; the algorithm text is the public standard. -/

/-- FIPS 204 Algorithm 43, `BitRev8`. -/
def bitRev8 (x : Nat) : Nat :=
  (x % 2) * 128 + (x / 2 % 2) * 64 + (x / 4 % 2) * 32 + (x / 8 % 2) * 16
    + (x / 16 % 2) * 8 + (x / 32 % 2) * 4 + (x / 64 % 2) * 2 + (x / 128 % 2)

theorem bitRev8_lt (x : Nat) : bitRev8 x < 256 := by
  have h0 : x % 2 < 2 := Nat.mod_lt _ (by decide)
  have h1 : x / 2 % 2 < 2 := Nat.mod_lt _ (by decide)
  have h2 : x / 4 % 2 < 2 := Nat.mod_lt _ (by decide)
  have h3 : x / 8 % 2 < 2 := Nat.mod_lt _ (by decide)
  have h4 : x / 16 % 2 < 2 := Nat.mod_lt _ (by decide)
  have h5 : x / 32 % 2 < 2 := Nat.mod_lt _ (by decide)
  have h6 : x / 64 % 2 < 2 := Nat.mod_lt _ (by decide)
  have h7 : x / 128 % 2 < 2 := Nat.mod_lt _ (by decide)
  simp only [bitRev8]
  omega

/-- FIPS 204 Algorithm 35 `Power2Round`. Returns `(r1, r0)`. -/
def fipsPower2Round (r : Int) : Int × Int :=
  let rp := r % Q
  let r0 := modPM rp (2 ^ D)
  ( (rp - r0) / (2 ^ D), r0 )

/-- FIPS 204 Algorithm 36 `Decompose`. Returns `(r1, r0)`. -/
def fipsDecompose (r gamma2 : Int) : Int × Int :=
  let rp := r % Q
  let alpha := 2 * gamma2
  let r0 := modPM rp alpha
  if rp - r0 = Q - 1 then
    (0, r0 - 1)
  else
    ((rp - r0) / alpha, r0)

/-- FIPS 204 Algorithm 37. -/
def fipsHighBits (r gamma2 : Int) : Int := (fipsDecompose r gamma2).1

/-- FIPS 204 Algorithm 38. -/
def fipsLowBits (r gamma2 : Int) : Int := (fipsDecompose r gamma2).2

/-- FIPS 204 Algorithm 39 `MakeHint(z, r)`. -/
def fipsMakeHint (z r gamma2 : Int) : Bool :=
  fipsHighBits r gamma2 ≠ fipsHighBits (r + z) gamma2

/-- FIPS 204 Algorithm 40 `UseHint(h, r)`. `h` is `0` or `1`. -/
def fipsUseHint (h r gamma2 : Int) : Int :=
  let m := (Q - 1) / (2 * gamma2)
  let (r1, r0) := fipsDecompose r gamma2
  if h = 0 then r1
  else if 0 < r0 then (r1 + 1) % m else (r1 - 1) % m

/-- Canonical FIPS zeta table: `ζ^{BitRev8(k)} mod q`, with slot 0 unused (`0`). -/
def fipsZeta (k : Nat) : Int :=
  if k = 0 then 0 else Zeta ^ bitRev8 k % Q

/-- Geometric sum `1 + x + … + x^{n-1}`. -/
def geomSum (x : Int) : Nat → Int
  | 0 => 0
  | n + 1 => geomSum x n + x ^ n

theorem geomSum_mul (x : Int) : (n : Nat) →
    geomSum x n * (x - 1) = x ^ n - 1
  | 0 => by
    simp [geomSum]
    omega
  | n + 1 => by
    have ih := geomSum_mul x n
    simp only [geomSum, Int.pow_succ]
    have : (geomSum x n + x ^ n) * (x - 1) =
        geomSum x n * (x - 1) + x ^ n * (x - 1) := by
      rw [Int.add_mul]
    rw [this, ih, Int.mul_sub, Int.mul_one]
    omega

/-- Evaluation of a length-256 polynomial at `x`. -/
def evalAt (a : Fin 256 → Int) (x : Int) : Int :=
  (List.range 256).foldl
    (fun s j => if h : j < 256 then s + a ⟨j, h⟩ * x ^ j else s) 0

end MlDsaArith
