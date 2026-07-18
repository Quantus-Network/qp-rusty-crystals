#!/usr/bin/env bash
# Off-device ML-DSA stack measurement for the Keystone3 / ForgeBox target.
#
# Builds the dilithium crate for the firmware's real target (thumbv7em-none-eabihf, release)
# with per-function stack-size emission, then reports the stack frame of every ML-DSA entry
# point plus the largest frames overall. Use this BEFORE flashing to catch stack regressions
# (e.g. re-introducing a fully materialized matrix) without touching hardware.
#
# Ground truth for total task stack is still the on-device FreeRTOS high-water mark; this gives
# the per-function frames that dominate it.
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
READOBJ="$(rustup run "$TOOLCHAIN" rustc --print sysroot)/lib/rustlib/$HOST/bin/llvm-readobj"

echo "Building dilithium for $TARGET ($TOOLCHAIN) with -Z emit-stack-sizes ..."
RUSTFLAGS="-Z emit-stack-sizes" rustup run "$TOOLCHAIN" cargo build --release \
  -p qp-rusty-crystals-dilithium --target "$TARGET" --no-default-features >/dev/null

RLIB="${CARGO_TARGET_DIR:-$ROOT/target}/$TARGET/release/libqp_rusty_crystals_dilithium.rlib"
"$READOBJ" --stack-sizes "$RLIB" > /tmp/dilithium_stack_sizes.txt

python3 - "$@" <<'PY'
import re, sys
txt = open('/tmp/dilithium_stack_sizes.txt').read()
pairs = re.findall(r'Functions:\s*\[(.+?)\]\s*\n\s*Size:\s*(0x[0-9A-Fa-f]+)', txt)

def demangle(sym):
    m = re.match(r'_ZN(.+?)E(\.llvm\..*)?$', sym)
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

rows = sorted(((int(sz, 16), demangle(f)) for f, sz in pairs), reverse=True)
def frame(name):
    for s, f in rows:
        if f.endswith('::' + name) or f.split('::')[-1] == name:
            return s
    return 0

print("\n=== thumbv7em per-function stack frames (bytes) ===")
print("  top frames:")
for s, f in rows[:8]:
    print(f"    {s:8d}  {f}")
print("\n  ML-DSA entry points (single frame, callees add a few KB on top):")
for name in ('keypair', 'verify', 'signature'):
    print(f"    {frame(name):8d}  sign::{name}")

budget_kb = int(sys.argv[1]) if len(sys.argv) > 1 else 0
if budget_kb:
    worst = max(frame('signature'), frame('verify'), frame('keypair'))
    print(f"\n  budget: {budget_kb} KB, worst single frame: {worst/1024:.1f} KB")
    if worst > budget_kb * 1024:
        print("  FAIL: a frame exceeds the budget")
        sys.exit(1)
    print("  OK")
PY
