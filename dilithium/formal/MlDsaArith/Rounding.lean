import MlDsaArith.Params
import MlDsaArith.Reduce
import MlDsaArith.Fips204

namespace MlDsaArith

/-! Line-for-line models of `dilithium/src/rounding.rs`. -/

/-- `power2round` (`rounding.rs:38–47`). Returns `(a0, a1)`. -/
def rustPower2Round (a : Int) : Int × Int :=
  let a := caddq a
  let a1 := ashr (a + 2 ^ (D - 1) - 1) D
  let a0 := a - a1 * 2 ^ D
  (a0, a1)

/-- `decompose` for `GAMMA2 = (Q-1)/32` (`rounding.rs:77–99`). Returns `(a0, a1)`. -/
def rustDecompose32 (a : Int) : Int × Int :=
  let a := caddq a
  let a1 := ashr (a + 127) 7
  let a1 := ashr (a1 * 1025 + 2 ^ 21) 22
  let a1 := asI32 a1 &&& (15 : Int)
  let a0 := a - a1 * 2 * GAMMA2_32
  let a0 := a0 - (if 0 ≤ (Q - 1) / 2 - a0 then 0 else Q)
  (a0, a1)

/-- `decompose` for `GAMMA2 = (Q-1)/88`. -/
def rustDecompose88 (a : Int) : Int × Int :=
  let a := caddq a
  let a1 := ashr (a + 127) 7
  let a1 := ashr (a1 * 11275 + 2 ^ 23) 24
  let a1 :=
    let mask := ashr (43 - a1) 31
    a1 ^^^ (mask &&& a1)
  let a0 := a - a1 * 2 * GAMMA2_88
  let a0 := a0 - (if 0 ≤ (Q - 1) / 2 - a0 then 0 else Q)
  (a0, a1)

/-- Dilithium-round-3 overflow predicate (the `make_hint` spec). -/
def makeHintPred (gamma2 a0 a1 : Int) : Bool :=
  decide (gamma2 < a0 ∨ a0 < -gamma2 ∨ (a0 = -gamma2 ∧ a1 ≠ 0))

/-- `make_hint` (`rounding.rs:122–137`), modelled by the documented overflow
predicate. The bitwise `>> 31` form is proved equal on `i32` inputs. -/
def rustMakeHint (gamma2 a0 a1 : Int) : Int :=
  if makeHintPred gamma2 a0 a1 then 1 else 0

/-- Bitwise `make_hint` matching the Rust operators. -/
def rustMakeHintBits (gamma2 a0 a1 : Int) : Int :=
  let gt := ashr (gamma2 - a0) 31
  let t := a0 + gamma2
  let lt := ashr t 31
  let eq := ~~~ ashr (t ||| wrappingNeg32 t) 31
  let a1nz := ashr (a1 ||| wrappingNeg32 a1) 31
  (gt ||| lt ||| (eq &&& a1nz)) &&& (1 : Int)

/-- `use_hint` for `GAMMA2 = (Q-1)/32` (`rounding.rs:148–173`). -/
def rustUseHint32 (a hint : Int) : Int :=
  let (a0, a1) := rustDecompose32 a
  if hint = 0 then a1
  else if 0 < a0 then (a1 + 1) &&& (15 : Int) else (a1 - 1) &&& (15 : Int)

/-- `use_hint` for `GAMMA2 = (Q-1)/88`. -/
def rustUseHint88 (a hint : Int) : Int :=
  let (a0, a1) := rustDecompose88 a
  if hint = 0 then a1
  else if 0 < a0 then
    if a1 = 43 then 0 else a1 + 1
  else if a1 = 0 then 43 else a1 - 1

end MlDsaArith
