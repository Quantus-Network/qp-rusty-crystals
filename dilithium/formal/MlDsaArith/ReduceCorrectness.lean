import MlDsaArith.Params
import MlDsaArith.Reduce

namespace MlDsaArith

/-! ### Wrapping -/

theorem asI32_bounded (a : Int) : I32MIN ≤ asI32 a ∧ asI32 a ≤ I32MAX := by
  simp only [asI32, W32, I32MIN, I32MAX]
  split <;> omega

theorem asI32_of_bounded {a : Int} (hlo : I32MIN ≤ a) (hhi : a ≤ I32MAX) :
    asI32 a = a := by
  simp only [asI32, W32, I32MIN, I32MAX] at *
  by_cases hp : 0 ≤ a
  · have : a % (2 ^ 32) = a := Int.emod_eq_of_lt hp (by omega)
    split <;> omega
  · have hrem : a % (2 ^ 32) = a + 2 ^ 32 := by
      have hmod : (a + 2 ^ 32) % (2 ^ 32) = a + 2 ^ 32 :=
        Int.emod_eq_of_lt (by omega) (by omega)
      have hadd : (a + 2 ^ 32) % (2 ^ 32) = a % (2 ^ 32) := by
        rw [Int.add_emod, Int.emod_self, Int.add_zero, Int.emod_emod]
      omega
    split <;> omega

theorem asI32_emod (a : Int) : asI32 a % W32 = a % W32 := by
  simp only [asI32, W32]
  split
  · have : (a % (2 ^ 32) - 2 ^ 32) % (2 ^ 32) = a % (2 ^ 32) % (2 ^ 32) := by
      rw [Int.sub_emod, Int.emod_self, Int.sub_zero, Int.emod_emod]
    rw [this, Int.emod_emod]
  · exact Int.emod_emod a (2 ^ 32)

theorem wrappingMul32_emod (a b : Int) : wrappingMul32 a b % W32 = a * b % W32 :=
  asI32_emod (a * b)

theorem ashr_eq_ediv (a : Int) (k : Nat) : ashr a k = a / (2 ^ k) :=
  Int.fdiv_eq_ediv_of_nonneg a (Int.pow_nonneg (by decide : (0 : Int) ≤ 2))

theorem ashr31_of_i32 {a : Int} (hlo : I32MIN ≤ a) (hhi : a ≤ I32MAX) :
    ashr a 31 = signMask a := by
  rw [ashr_eq_ediv, signMask]
  simp only [I32MIN, I32MAX] at hlo hhi
  split
  · exact Int.ediv_eq_neg_one_of_neg_of_le ‹a < 0› (by omega)
  · exact Int.ediv_eq_zero_of_lt (by omega) (by omega)

/-! ### `caddq` (`reduce.rs:32–36`) -/

theorem caddq_of_nonneg {a : Int} (h : 0 ≤ a) : caddq a = a := by
  simp only [caddq]
  split <;> omega

theorem caddq_of_neg {a : Int} (h : a < 0) : caddq a = a + Q := by
  simp only [caddq]
  split <;> omega

theorem caddq_canonical {a : Int} (hlo : -Q < a) (hhi : a < Q) :
    0 ≤ caddq a ∧ caddq a < Q ∧ caddq a % Q = a % Q := by
  simp only [caddq]
  split
  · refine ⟨by omega, by omega, ?_⟩
    rw [Int.add_emod, Int.emod_self, Int.add_zero, Int.emod_emod]
  · refine ⟨by omega, by omega, ?_⟩
    simp

theorem caddq_44 : caddq 44 = 44 := by decide
theorem caddq_0 : caddq 0 = 0 := by decide
theorem caddq_neg123 : caddq (-123) = Q - 123 := by decide

/-! ### `i64` product `t * Q` never wraps for an `i32` `t` -/

private theorem natAbs_of_i32 {t : Int} (hlo : I32MIN ≤ t) (hhi : t ≤ I32MAX) :
    t.natAbs ≤ 2 ^ 31 := by
  simp only [I32MIN, I32MAX] at hlo hhi
  cases Int.le_total 0 t with
  | inl hp =>
    have : (t.natAbs : Int) = t := Int.natAbs_of_nonneg hp
    omega
  | inr hn =>
    have : (t.natAbs : Int) = -t := Int.ofNat_natAbs_of_nonpos hn
    omega

theorem asI64_of_bounded {a : Int} (hlo : -(2 ^ 63) < a) (hhi : a < 2 ^ 63) :
    asI64 a = a := by
  simp only [asI64, W64] at *
  by_cases hp : 0 ≤ a
  · have : a % (2 ^ 64) = a := Int.emod_eq_of_lt hp (by omega)
    split <;> omega
  · have hrem : a % (2 ^ 64) = a + 2 ^ 64 := by
      have hmod : (a + 2 ^ 64) % (2 ^ 64) = a + 2 ^ 64 :=
        Int.emod_eq_of_lt (by omega) (by omega)
      have hadd : (a + 2 ^ 64) % (2 ^ 64) = a % (2 ^ 64) := by
        rw [Int.add_emod, Int.emod_self, Int.add_zero, Int.emod_emod]
      omega
    split <;> omega

private theorem mul_Q_abs_lt_2_63 {t : Int} (hlo : I32MIN ≤ t) (hhi : t ≤ I32MAX) :
    (t * Q).natAbs < 2 ^ 63 := by
  have ht : t.natAbs ≤ 2 ^ 31 := natAbs_of_i32 hlo hhi
  have hQ : Q.natAbs = 8380417 := by decide
  have hprod : (t * Q).natAbs ≤ 2147483648 * 8380417 := by
    rw [Int.natAbs_mul, hQ]
    exact Nat.mul_le_mul_right _ ht
  have hlt : 2147483648 * 8380417 < 2 ^ 63 := by decide
  exact Nat.lt_of_le_of_lt hprod hlt

private theorem mul_Q_fits_i64 {t : Int} (hlo : I32MIN ≤ t) (hhi : t ≤ I32MAX) :
    -(2 ^ 63) < t * Q ∧ t * Q < 2 ^ 63 := by
  have habs : (t * Q).natAbs < 2 ^ 63 := mul_Q_abs_lt_2_63 hlo hhi
  have hcast : ((t * Q).natAbs : Int) < 2 ^ 63 := Int.ofNat_lt.mpr habs
  cases Int.natAbs_eq (t * Q) with
  | inl hp => omega
  | inr hn => omega

theorem wrappingMul64_Q {t : Int} (hlo : I32MIN ≤ t) (hhi : t ≤ I32MAX) :
    wrappingMul64 t Q = t * Q := by
  have ⟨hneg, hpos⟩ := mul_Q_fits_i64 hlo hhi
  simp only [wrappingMul64]
  exact asI64_of_bounded hneg hpos

/-! ### `montgomery_reduce` -/

private theorem t_emod (a : Int) :
    wrappingMul32 (asI32 a) Q_INV % W32 = a * Q_INV % W32 := by
  rw [wrappingMul32_emod, Int.mul_emod, asI32_emod, ← Int.mul_emod]

private theorem tQ_emod (a : Int) :
    wrappingMul32 (asI32 a) Q_INV * Q % W32 = a % W32 := by
  have h1 : wrappingMul32 (asI32 a) Q_INV * Q % W32
      = wrappingMul32 (asI32 a) Q_INV % W32 * (Q % W32) % W32 := by
    rw [Int.mul_emod]
  rw [h1, t_emod]
  have : a * Q_INV % W32 * (Q % W32) % W32 = a * Q_INV * Q % W32 := by
    rw [← Int.mul_emod]
  rw [this, Int.mul_assoc]
  have hinv : Q_INV * Q % W32 = 1 := Q_INV_spec
  rw [Int.mul_emod a (Q_INV * Q), hinv, Int.mul_one, Int.emod_emod]

private theorem mont_t_bounded (a : Int) :
    I32MIN ≤ wrappingMul32 (asI32 a) Q_INV ∧
      wrappingMul32 (asI32 a) Q_INV ≤ I32MAX :=
  asI32_bounded _

private theorem mont_diff_dvd (a : Int) :
    W32 ∣ a - wrappingMul32 (asI32 a) Q_INV * Q := by
  have hcong : (a - wrappingMul32 (asI32 a) Q_INV * Q) % W32 = 0 := by
    have := tQ_emod a
    rw [Int.sub_emod, this, Int.sub_self, Int.zero_emod]
  exact Int.dvd_of_emod_eq_zero hcong

private theorem montgomeryReduce_eq_ediv (a : Int) :
    montgomeryReduce a =
      (a - wrappingMul32 (asI32 a) Q_INV * Q) / W32 := by
  have ht := mont_t_bounded a
  have hwrap := wrappingMul64_Q ht.1 ht.2
  simp only [montgomeryReduce, ashr_eq_ediv, W32]
  rw [hwrap]

private theorem montgomeryReduce_mul_W32 (a : Int) :
    montgomeryReduce a * W32 = a - wrappingMul32 (asI32 a) Q_INV * Q := by
  have hdvd := mont_diff_dvd a
  rw [montgomeryReduce_eq_ediv]
  exact Int.ediv_mul_cancel hdvd

theorem montgomeryReduce_dvd (a : Int) :
    Q ∣ montgomeryReduce a * W32 - a := by
  rw [montgomeryReduce_mul_W32]
  refine ⟨-wrappingMul32 (asI32 a) Q_INV, ?_⟩
  let t := wrappingMul32 (asI32 a) Q_INV
  have : a - t * Q - a = -(t * Q) := by omega
  rw [this, Int.mul_comm t Q, Int.mul_neg]

theorem montgomeryReduce_mod (a : Int) :
    montgomeryReduce a * W32 % Q = a % Q := by
  obtain ⟨k, hk⟩ := montgomeryReduce_dvd a
  have : montgomeryReduce a * W32 = a + Q * k := by omega
  rw [this, Int.add_mul_emod_self_left]

theorem montgomeryReduce_bounds {a : Int}
    (hlo : -2 ^ 31 * Q ≤ a) (hhi : a < 2 ^ 31 * Q) :
    -Q < montgomeryReduce a ∧ montgomeryReduce a < Q := by
  have ht := mont_t_bounded a
  have hmul := montgomeryReduce_mul_W32 a
  simp only [Q, W32, I32MIN, I32MAX] at *
  constructor
  · by_cases hr : montgomeryReduce a ≤ -8380417
    · have h1 : montgomeryReduce a * 4294967296 ≤ -8380417 * 4294967296 :=
        Int.mul_le_mul_of_nonneg_right hr (by decide)
      have h2 : a - wrappingMul32 (asI32 a) Q_INV * 8380417 ≤ -8380417 * 4294967296 := by
        rw [← hmul]; exact h1
      have h3 : a ≤ wrappingMul32 (asI32 a) Q_INV * 8380417 - 8380417 * 4294967296 := by
        omega
      have h4 : wrappingMul32 (asI32 a) Q_INV ≤ 2147483647 := ht.2
      have h5 : wrappingMul32 (asI32 a) Q_INV * 8380417 ≤ 2147483647 * 8380417 :=
        Int.mul_le_mul_of_nonneg_right h4 (by decide)
      omega
    · omega
  · by_cases hr : 8380417 ≤ montgomeryReduce a
    · have h1 : 8380417 * 4294967296 ≤ montgomeryReduce a * 4294967296 :=
        Int.mul_le_mul_of_nonneg_right hr (by decide)
      have h2 : 8380417 * 4294967296 ≤ a - wrappingMul32 (asI32 a) Q_INV * 8380417 := by
        rw [← hmul]; exact h1
      have h3 : wrappingMul32 (asI32 a) Q_INV ≥ -2147483648 := ht.1
      have h4 : wrappingMul32 (asI32 a) Q_INV * 8380417 ≥ -2147483648 * 8380417 :=
        Int.mul_le_mul_of_nonneg_right h3 (by decide)
      omega
    · omega

theorem montgomeryReduce_excluded_endpoint :
    montgomeryReduce (2 ^ 31 * Q) = Q := by decide

/-! ### `reduce32` -/

private theorem reduce32_t_eq (a : Int) :
    ashr (a + 2 ^ 22) 23 = (a + 2 ^ 22) / (2 ^ 23) :=
  ashr_eq_ediv _ _

private theorem reduce32_t_bounded {a : Int}
    (hlo : I32MIN ≤ a) (hhi : a ≤ I32MAX) :
    -256 ≤ ashr (a + 2 ^ 22) 23 ∧ ashr (a + 2 ^ 22) 23 ≤ 256 := by
  rw [reduce32_t_eq]
  have hden : (0 : Int) < 2 ^ 23 := by decide
  have hlo' : (I32MIN + 2 ^ 22) / (2 ^ 23) ≤ (a + 2 ^ 22) / (2 ^ 23) :=
    Int.ediv_le_ediv hden (by omega)
  have hhi' : (a + 2 ^ 22) / (2 ^ 23) ≤ (I32MAX + 2 ^ 22) / (2 ^ 23) :=
    Int.ediv_le_ediv hden (by omega)
  have hmin : (I32MIN + 2 ^ 22) / (2 ^ 23) = -256 := by
    simp only [I32MIN]
    decide
  have hmax : (I32MAX + 2 ^ 22) / (2 ^ 23) = 256 := by
    simp only [I32MAX]
    decide
  omega

private theorem reduce32_tQ_no_wrap {a : Int}
    (hlo : I32MIN ≤ a) (hhi : a ≤ I32MAX) :
    wrappingMul32 (ashr (a + 2 ^ 22) 23) Q = ashr (a + 2 ^ 22) 23 * Q := by
  simp only [I32MIN, I32MAX] at hlo hhi
  let t := ashr (a + 2 ^ 22) 23
  have ht := reduce32_t_bounded (by simp only [I32MIN]; exact hlo)
    (by simp only [I32MAX]; exact hhi)
  have htAbs : t.natAbs ≤ 256 := by
    cases Int.le_total 0 t with
    | inl hp =>
      have : (t.natAbs : Int) = t := Int.natAbs_of_nonneg hp
      omega
    | inr hn =>
      have : (t.natAbs : Int) = -t := Int.ofNat_natAbs_of_nonpos hn
      omega
  have hQ : Q.natAbs = 8380417 := by decide
  have hprod : (t * Q).natAbs ≤ 256 * 8380417 := by
    rw [Int.natAbs_mul, hQ]
    exact Nat.mul_le_mul_right _ htAbs
  have hfit : 256 * 8380417 ≤ 2147483647 := by decide
  have habs : (t * Q).natAbs ≤ 2147483647 := Nat.le_trans hprod hfit
  have hcast : ((t * Q).natAbs : Int) ≤ I32MAX := by
    simp only [I32MAX]
    exact Int.ofNat_le.mpr habs
  have hlo' : I32MIN ≤ t * Q := by
    simp only [I32MIN]
    cases Int.natAbs_eq (t * Q) with
    | inl hp => omega
    | inr hn => omega
  have hhi' : t * Q ≤ I32MAX := by
    simp only [I32MAX]
    cases Int.natAbs_eq (t * Q) with
    | inl hp => omega
    | inr hn => omega
  simp only [wrappingMul32]
  exact asI32_of_bounded hlo' hhi'

theorem reduce32_mod {a : Int} (hlo : I32MIN ≤ a) (hhi : a ≤ I32MAX) :
    (reduce32 a - a) % Q = 0 := by
  have hwrap := reduce32_tQ_no_wrap hlo hhi
  simp only [reduce32, hwrap]
  have : a - ashr (a + 2 ^ 22) 23 * Q - a =
      -(ashr (a + 2 ^ 22) 23 * Q) := by omega
  rw [this, Int.neg_mul_emod_left]

theorem reduce32_mod' {a : Int} (hlo : I32MIN ≤ a) (hhi : a ≤ I32MAX) :
    reduce32 a % Q = a % Q := by
  have h : (reduce32 a - a) % Q = 0 := reduce32_mod hlo hhi
  have : reduce32 a = a + (reduce32 a - a) := by omega
  rw [this, Int.add_emod, h, Int.add_zero, Int.emod_emod]

/-- Barrett remainder. The C/Rust comment claims `[-6283008, 6283008]`; the
tight range on every `i32` with `a ≤ 2^{31}-2^{22}-1` is `[-6291200, 6283008]`
(the C/Rust comment's `-6283008` is the typical Barrett figure; the extra
room is the `t = -256` i32-minimum case). -/
theorem reduce32_bounds {a : Int}
    (hlo : I32MIN ≤ a) (hhi : a ≤ 2 ^ 31 - 2 ^ 22 - 1) :
    -6291200 ≤ reduce32 a ∧ reduce32 a ≤ 6283008 := by
  have hhiI : a ≤ I32MAX := by
    simp only [I32MAX]
    omega
  have hwrap := reduce32_tQ_no_wrap hlo hhiI
  have ht := reduce32_t_bounded hlo hhiI
  have tEq : ashr (a + 2 ^ 22) 23 = (a + 2 ^ 22) / (2 ^ 23) := reduce32_t_eq a
  have hred : reduce32 a = a - (a + 2 ^ 22) / (2 ^ 23) * Q := by
    simp only [reduce32]
    rw [hwrap, tEq]
  have hdiv := Int.ediv_mul_add_emod (a + 2 ^ 22) (2 ^ 23)
  have hrem_lo : 0 ≤ (a + 2 ^ 22) % (2 ^ 23) :=
    Int.emod_nonneg _ (by decide : (2 : Int) ^ 23 ≠ 0)
  have hrem_hi : (a + 2 ^ 22) % (2 ^ 23) < 2 ^ 23 :=
    Int.emod_lt_of_pos _ (by decide : (0 : Int) < 2 ^ 23)
  have h8191 : (2 : Int) ^ 23 - Q = 8191 := by
    simp only [Q]
    decide
  have hform : reduce32 a =
      (a + 2 ^ 22) / (2 ^ 23) * 8191 + (a + 2 ^ 22) % (2 ^ 23) - 2 ^ 22 := by
    have hpow : (2 : Int) ^ 23 = 8388608 := by decide
    simp only [hred, Q, hpow] at *
    omega
  have hhiT : (a + 2 ^ 22) / (2 ^ 23) ≤ 255 := by
    have hden : (0 : Int) < 2 ^ 23 := by decide
    have : (a + 2 ^ 22) / (2 ^ 23) ≤ (2 ^ 31 - 1) / (2 ^ 23) :=
      Int.ediv_le_ediv hden (by omega)
    have : (2 ^ 31 - 1 : Int) / (2 ^ 23) = 255 := by decide
    omega
  have htLo : -256 ≤ (a + 2 ^ 22) / (2 ^ 23) := by
    rw [← tEq]
    exact ht.1
  clear hlo hhi hhiI ht hwrap tEq hred hdiv hrem_lo h8191
  constructor
  · have : reduce32 a ≥ (a + 2 ^ 22) / (2 ^ 23) * 8191 - 2 ^ 22 := by
      rw [hform]
      omega
    have : (a + 2 ^ 22) / (2 ^ 23) * 8191 ≥ (-256 : Int) * 8191 :=
      Int.mul_le_mul_of_nonneg_right htLo (by decide)
    omega
  · have : reduce32 a ≤ (a + 2 ^ 22) / (2 ^ 23) * 8191 + (2 ^ 23 - 1) - 2 ^ 22 := by
      rw [hform]
      omega
    have : (a + 2 ^ 22) / (2 ^ 23) * 8191 ≤ (255 : Int) * 8191 :=
      Int.mul_le_mul_of_nonneg_right hhiT (by decide)
    omega

theorem reduce32_0 : reduce32 0 = 0 := by decide

/-! ### Kernel-eval of the crate's unit-test points -/

example : montgomeryReduce 0 = 0 := by decide
example : montgomeryReduce 23 = -2635616 := by decide
example : montgomeryReduce (2 ^ 31 * Q) = Q := by decide
example : -Q < montgomeryReduce (-(2 ^ 31) * Q) ∧ montgomeryReduce (-(2 ^ 31) * Q) < Q := by
  decide
example : -Q < montgomeryReduce (2 ^ 31 * Q - 1) ∧ montgomeryReduce (2 ^ 31 * Q - 1) < Q := by
  decide

end MlDsaArith
