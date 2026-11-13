#!/usr/bin/env bash
# Off-device ML-DSA stack measurement for the Keystone3 / ForgeBox target.
#
# Builds the dilithium crate for the firmware's real target (thumbv7em-none-eabihf, release)
# with per-function stack-size emission, once per ML-DSA parameter set, then reports the
# worst-case stack of every ML-DSA entry point: its own frame plus the deepest chain of
# callees, read from the call relocations in the compiled crate. Use this BEFORE flashing to
# catch stack regressions (e.g. re-introducing a fully materialized matrix) without touching
# hardware.
#
# Ground truth for total task stack is still the on-device FreeRTOS high-water mark. Calls
# that leave the crate (the memory intrinsics, panic paths) and indirect calls are not
# followed, so the on-device figure is slightly higher.
#
# Usage: ./stack-check.sh [budget_kb]
#   ML_DSA_SETS="44 65 87"   parameter sets to measure (default: all three)
# With a budget, exits non-zero when any entry point exceeds it. An entry point that cannot
# be measured is always an error.
set -euo pipefail

TOOLCHAIN="${RUST_TOOLCHAIN:-nightly-2025-07-01}"
TARGET="thumbv7em-none-eabihf"
ROOT="$(cd "$(dirname "$0")" && pwd)"

# Nightly is required for -Z emit-stack-sizes; llvm-readobj ships with the llvm-tools
# component, not the base toolchain. All three installs are idempotent.
rustup toolchain install "$TOOLCHAIN" --profile minimal >/dev/null
rustup target add "$TARGET" --toolchain "$TOOLCHAIN" >/dev/null
rustup component add llvm-tools --toolchain "$TOOLCHAIN" >/dev/null

HOST="$(rustup run "$TOOLCHAIN" rustc -vV | sed -n 's/host: //p')"
LLVM_BIN="$(rustup run "$TOOLCHAIN" rustc --print sysroot)/lib/rustlib/$HOST/bin"
RLIB="${CARGO_TARGET_DIR:-$ROOT/target}/$TARGET/release/libqp_rusty_crystals_dilithium.rlib"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

for SET in ${ML_DSA_SETS:-44 65 87}; do
  echo "Building dilithium (ml-dsa-$SET) for $TARGET ($TOOLCHAIN) with -Z emit-stack-sizes ..."
  RUSTFLAGS="-Z emit-stack-sizes" rustup run "$TOOLCHAIN" cargo build --release \
    -p qp-rusty-crystals-dilithium --target "$TARGET" --no-default-features \
    --features "ml-dsa-$SET" >/dev/null

  "$LLVM_BIN/llvm-readobj" --stack-sizes "$RLIB" > "$OUT/stack_sizes.txt"
  "$LLVM_BIN/llvm-objdump" -d -r --no-show-raw-insn "$RLIB" > "$OUT/disassembly.txt"

  python3 - "$SET" "$OUT/stack_sizes.txt" "$OUT/disassembly.txt" "$@" <<'PY'
import re, sys
param_set, sizes_path, disassembly_path = sys.argv[1:4]
budget_kb = int(sys.argv[4]) if len(sys.argv) > 4 else 0

def symbol(name):
    return re.sub(r'\.llvm\.\d+$', '', name.strip())

def demangle(sym):
    m = re.match(r'_ZN(.+?)E$', sym)
    if not m: return sym
    s, out, i = m.group(1), [], 0
    while i < len(s):
        j = i
        while j < len(s) and s[j].isdigit(): j += 1
        if j == i: break
        n = int(s[i:j]); seg = s[j:j+n]
        if not re.fullmatch(r'h[0-9a-f]{16}', seg): out.append(seg)
        i = j + n
    return '::'.join(out)

frames = {}
pairs = re.findall(r'Functions:\s*\[(.+?)\]\s*\n\s*Size:\s*(0x[0-9A-Fa-f]+)', open(sizes_path).read())
for functions, size in pairs:
    for f in functions.split(','):
        frames[symbol(f)] = max(frames.get(symbol(f), 0), int(size, 16))

calls, current = {}, None
for line in open(disassembly_path):
    header = re.match(r'[0-9a-f]+ <(.+)>:$', line)
    if header:
        current = symbol(header.group(1))
        continue
    call = re.search(r'R_ARM_THM_(?:CALL|JUMP24)\s+(\S+)', line)
    if call and current:
        calls.setdefault(current, set()).add(symbol(call.group(1)))

totals = {}
def total(f, chain=()):
    if f not in totals:
        if f in chain:
            sys.exit(f"FAIL: recursion through {demangle(f)}, worst-case stack is unbounded")
        callees = [total(c, chain + (f,)) for c in calls.get(f, ()) if c in frames]
        totals[f] = frames[f] + max(callees, default=0)
    return totals[f]

print(f"\n=== ML-DSA-{param_set}: thumbv7em worst-case stack (bytes) ===")
print("  top frames:")
for f in sorted(frames, key=frames.get, reverse=True)[:8]:
    print(f"    {frames[f]:8d}  {demangle(f)}")
print("\n  ML-DSA entry points (own frame plus deepest callee chain):")
worst = 0
for entry in ('Keypair::generate', 'Keypair::from_bytes', 'SecretKey::from_bytes',
              'SecretKey::sign', 'PublicKey::verify'):
    found = [f for f in frames if demangle(f).endswith(f"::ml_dsa_{param_set}::{entry}")]
    if len(found) != 1 or not calls.get(found[0]):
        sys.exit(f"FAIL: cannot measure {entry}: {len(found)} matching symbols with a call graph")
    worst = max(worst, total(found[0]))
    print(f"    {total(found[0]):8d}  {entry}")

if budget_kb:
    print(f"\n  budget: {budget_kb} KB, worst entry point: {worst/1024:.1f} KB")
    if worst > budget_kb * 1024:
        sys.exit("  FAIL: an entry point exceeds the budget")
    print("  OK")
PY
done
