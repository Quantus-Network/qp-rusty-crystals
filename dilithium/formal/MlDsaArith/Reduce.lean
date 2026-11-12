/-
  Line-for-line transcription of `dilithium/src/reduce.rs`.
-/

import MlDsaArith.Params

namespace MlDsaArith

/-- `montgomery_reduce` (`reduce.rs:13–16`):
```rust
let mut t = (a as i32).wrapping_mul(Q_INV) as i64;
t = (a - t.wrapping_mul(Q as i64)) >> 32;
t as i32
``` -/
def montgomeryReduce (a : Int) : Int :=
  let t := wrappingMul32 (asI32 a) Q_INV
  let t2 := a - wrappingMul64 t Q
  ashr t2 32

/-- `reduce32` (`reduce.rs:23–26`):
```rust
let mut t = (a + (1 << 22)) >> 23;
t = a - t.wrapping_mul(Q);
t
``` -/
def reduce32 (a : Int) : Int :=
  let t := ashr (a + 2 ^ 22) 23
  a - wrappingMul32 t Q

/-- `caddq` (`reduce.rs:32–36`): `a + ((a >> 31) & Q)`.
On an `i32`, `(a >> 31) & Q` is `Q` if `a < 0` and `0` otherwise. -/
def caddq (a : Int) : Int :=
  a + if a < 0 then Q else 0

end MlDsaArith
