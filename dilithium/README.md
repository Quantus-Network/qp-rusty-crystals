# Quantus Network CRYSTALS-Dilithium

Pure Rust implementation of ML-DSA (CRYSTALS-Dilithium) post-quantum digital signatures, supporting all three FIPS 204 parameter sets.

## Features

- **ML-DSA-44 / 65 / 87** - All FIPS 204 security levels behind additive Cargo features
- **Pure Rust** - No unsafe code, memory-safe implementation
- **NO-STD** - Does not depend on standard library so more portable
- **NIST Compliant** - Verified against official ACVP known-answer test vectors
- **Reasonably Constant-Time** - [Reasonably constant-time execution for keygen and signing](CONSTANT_TIME_TESTING.md)
- **Context String Support** - Support for domain separation contexts

### Cargo features

| Feature | Default | Module |
|---------|---------|--------|
| `ml-dsa-87` | yes | `ml_dsa_87` |
| `ml-dsa-65` | no | `ml_dsa_65` |
| `ml-dsa-44` | no | `ml_dsa_44` |

Features are additive: enable any combination so one binary can verify (or sign) at multiple levels.

```toml
[dependencies]
# Default: ML-DSA-87 only
qp-rusty-crystals-dilithium = "3.0.1"

# Or enable several levels:
qp-rusty-crystals-dilithium = { version = "3.0.1", features = ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"] }
```

## Usage

### Basic Example

```rust
use qp_rusty_crystals_dilithium::ml_dsa_87;

// Generate a keypair with secure random entropy
let mut entropy = [0u8; 32];
getrandom::getrandom(&mut entropy).expect("Failed to generate entropy");
let keypair = ml_dsa_87::Keypair::generate(&mut (&mut entropy).into());

// Sign a message
let message = b"Hello, post-quantum world!";
let signature = keypair.sign(message, None, None).expect("Signing should succeed");

// Verify the signature
let is_valid = keypair.verify(message, signature.as_slice(), None);
assert!(is_valid);
```

### Advanced Usage with Context Strings

```rust
use qp_rusty_crystals_dilithium::ml_dsa_87;

let mut entropy = [0u8; 32];
getrandom::getrandom(&mut entropy).expect("Failed to generate entropy");
let keypair = ml_dsa_87::Keypair::generate(&mut (&mut entropy).into());

let message = b"Important message";
let context = b"email-signature-v1"; // Domain separation

let signature = keypair.sign(message, Some(context), None).expect("Signing should succeed");
let is_valid = keypair.verify(message, signature.as_slice(), Some(context));
assert!(is_valid);
```

### Hedged Signing (Deterministic with Entropy)

```rust
use qp_rusty_crystals_dilithium::{ml_dsa_87, SensitiveBytes32};

let mut entropy = [0u8; 32];
getrandom::getrandom(&mut entropy).expect("Failed to generate entropy");
let keypair = ml_dsa_87::Keypair::generate(&mut (&mut entropy).into());

let message = b"Message to sign";

let mut hedge_entropy = [0u8; 32];
getrandom::getrandom(&mut hedge_entropy).expect("Failed to generate hedge entropy");
// Move the hedge into a self-wiping wrapper (this zeroes `hedge_entropy`);
// `sign` borrows it, so no unwiped copy of the randomizer is left behind.
let hedge = SensitiveBytes32::new(&mut hedge_entropy);

let signature = keypair
	.sign(message, None, Some(&hedge))
	.expect("Signing should succeed");
let is_valid = keypair.verify(message, signature.as_slice(), None);
assert!(is_valid);
```

## Security Levels

| Variant | Security Level | Public Key | Secret Key | Signature |
|---------|----------------|------------|------------|-----------|
| ML-DSA-44 | ~128 bits | 1,312 bytes | 2,560 bytes | 2,420 bytes |
| ML-DSA-65 | ~192 bits | 1,952 bytes | 4,032 bytes | 3,309 bytes |
| ML-DSA-87 | ~256 bits | 2,592 bytes | 4,896 bytes | 4,627 bytes |

## API Reference

### Keypair Generation

```rust
pub fn generate(entropy: SensitiveBytes32) -> Keypair
```

Generates a new keypair using the provided entropy. The entropy must be 32 bytes of cryptographically secure random data (e.g., from `getrandom::getrandom()`).

**Security Warning**: Never use predictable or human-readable strings as entropy. This includes:
- Hardcoded strings like `b"my_seed"`
- User passwords or passphrases
- Timestamps or counters
- Any deterministic data

Always use a cryptographically secure random number generator.

### Signing

```rust
pub fn sign(&self, msg: &[u8], ctx: Option<&[u8]>, hedge: Option<[u8; 32]>) -> Result<Signature, SignatureError>
```

- `msg`: The message to sign
- `ctx`: Optional context string for domain separation (max 255 bytes)
- `hedge`: Optional 32-byte entropy for hedged signing

### Verification

```rust
pub fn verify(&self, msg: &[u8], sig: &[u8], ctx: Option<&[u8]>) -> bool
```

- `msg`: The message that was signed
- `sig`: The signature to verify
- `ctx`: Optional context string (must match the one used for signing)

## Stack Usage

This implementation is not optimized for constrained environments and may not work with small stack sizes:

- Key generation: ≤256KB stack
- Signing: ≤256KB stack
- Verification: ≤256KB stack

See `examples/stack_usage_demo.rs` for detailed stack usage analysis.

## Testing

```bash
# Default feature set (ML-DSA-87)
cargo test -p qp-rusty-crystals-dilithium

# All parameter sets (ACVP KATs for 44/65/87)
cargo test -p qp-rusty-crystals-dilithium --all-features
```

## Benchmarks

```bash
cargo bench -p qp-rusty-crystals-dilithium --all-features
```

## Examples

```bash
# Run the stack usage demonstration
cargo run --example stack_usage_demo -p qp-rusty-crystals-dilithium
```

## License

GPL-3.0 - See [LICENSE](LICENSE) for details.
