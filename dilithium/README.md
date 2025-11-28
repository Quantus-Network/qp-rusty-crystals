# Quantus Network CRYSTALS-Dilithium

Pure Rust implementation of the ML-DSA-87 (CRYSTALS-Dilithium) post-quantum digital signature scheme.

## Features

- **ML-DSA-87 Only** - Highest security level implementation (~256-bit security)
- **Pure Rust** - No unsafe code, memory-safe implementation
- **NO-STD** - Does not depend on standard library so more portable
- **NIST Compliant** - Verified against official test vectors
- **Reasonably Constant-Time** - [Reasonably constant-time execution for keygen and signing](CONSTANT_TIME_TESTING.md)
- **Context String Support** - Support for domain separation contexts

## Usage

Add to your `Cargo.toml`:
```toml
[dependencies]
qp-rusty-crystals-dilithium = "2.0.0"
```

### Basic Example

```rust
use qp_rusty_crystals_dilithium::ml_dsa_87;

// Generate a keypair with secure random entropy
let mut entropy = [0u8; 32];
getrandom::getrandom(&mut entropy).expect("Failed to generate entropy");
let keypair = ml_dsa_87::Keypair::generate((&mut entropy).into());

// Alternative: you could also use a different secure entropy source
// let keypair = ml_dsa_87::Keypair::generate(&other_secure_entropy);

// Sign a message
let message = b"Hello, post-quantum world!";
let signature = keypair.sign(message, None, None);

// Verify the signature
let is_valid = keypair.verify(message, &signature, None);
assert!(is_valid);
```

### Advanced Usage with Context Strings

```rust
use qp_rusty_crystals_dilithium::ml_dsa_87;

// Generate secure entropy
let mut entropy = [0u8; 32];
getrandom::getrandom(&mut entropy).expect("Failed to generate entropy");
let keypair = ml_dsa_87::Keypair::generate((&mut entropy).into());

let message = b"Important message";
let context = b"email-signature-v1"; // Domain separation

// Sign with context
let signature = keypair.sign(message, Some(context), None);

// Verify with context
let is_valid = keypair.verify(message, &signature, Some(context));
assert!(is_valid);
```

### Hedged Signing (Deterministic with Entropy)

```rust
use qp_rusty_crystals_dilithium::ml_dsa_87;

// Generate secure entropy for keypair
let mut entropy = [0u8; 32];
getrandom::getrandom(&mut entropy).expect("Failed to generate entropy");
let keypair = ml_dsa_87::Keypair::generate((&mut entropy).into());

let message = b"Message to sign";

// Generate secure hedge entropy
let mut hedge_entropy = [0u8; 32];
getrandom::getrandom(&mut hedge_entropy).expect("Failed to generate hedge entropy");

// Hedged signing provides additional randomness
let signature = keypair.sign(message, None, Some(hedge_entropy));
let is_valid = keypair.verify(message, &signature, None);
assert!(is_valid);
```

## Security Level

| Variant | Security Level | Public Key Size | Private Key Size | Signature Size |
|---------|----------------|-----------------|------------------|----------------|
| ML-DSA-87 | ~256 bits | 2,592 bytes | 4,896 bytes | 4,627 bytes |

**Note**: This implementation only supports ML-DSA-87, the highest security variant. Other variants (ML-DSA-44, ML-DSA-65) are not implemented.

## API Reference

### Keypair Generation

```rust
pub fn generate(entropy: &[u8]) -> Keypair
```

Generates a new keypair using the provided entropy. The entropy must be at least 32 bytes of cryptographically secure random data (e.g., from `getrandom::getrandom()`).

**⚠️ Security Warning**: Never use predictable or human-readable strings as entropy. This includes:
- Hardcoded strings like `b"my_seed"`
- User passwords or passphrases
- Timestamps or counters
- Any deterministic data

Always use a cryptographically secure random number generator.

### Signing

```rust
pub fn sign(&self, msg: &[u8], ctx: Option<&[u8]>, hedge: Option<[u8; 32]>) -> Signature
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
cargo test
```

## Benchmarks

```bash
cargo bench
```

## Examples

```bash
# Run the stack usage demonstration
cargo run --example stack_usage_demo
```

## License

GPL-3.0 - See [LICENSE](LICENSE) for details.