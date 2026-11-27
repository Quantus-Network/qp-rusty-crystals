# qp-rusty-crystals-sphincs

A pure Rust implementation of SLH-DSA, the stateless hash-based signature scheme that FIPS 205 standardized from SPHINCS+. It is `no_std` and has no unsafe code.

SLH-DSA is not the round 3 SPHINCS+ submission. FIPS 205 changed the scheme, so signatures and known-answer tests of the two do not match. This crate implements FIPS 205 only.

## Parameter sets

All twelve FIPS 205 parameter sets are available, each as its own module.

| Module | Category | Public key | Secret key | Signature |
|--------|----------|------------|------------|-----------|
| `slh_dsa_sha2_128s`, `slh_dsa_shake_128s` | 1 | 32 | 64 | 7,856 |
| `slh_dsa_sha2_128f`, `slh_dsa_shake_128f` | 1 | 32 | 64 | 17,088 |
| `slh_dsa_sha2_192s`, `slh_dsa_shake_192s` | 3 | 48 | 96 | 16,224 |
| `slh_dsa_sha2_192f`, `slh_dsa_shake_192f` | 3 | 48 | 96 | 35,664 |
| `slh_dsa_sha2_256s`, `slh_dsa_shake_256s` | 5 | 64 | 128 | 29,792 |
| `slh_dsa_sha2_256f`, `slh_dsa_shake_256f` | 5 | 64 | 128 | 49,856 |

Sizes are in bytes. The `s` sets have small signatures and sign slowly. The `f` sets sign fast and have large signatures.

## Usage

```rust
use qp_rusty_crystals_sphincs::slh_dsa_sha2_256s::{Keypair, SEEDBYTES};

let mut seed = [0u8; SEEDBYTES];
getrandom::getrandom(&mut seed).expect("no entropy");
let keypair = Keypair::generate(&mut seed); // the seed is wiped

let signature = keypair.sign(b"message", Some(b"context"), None)?;
assert!(keypair.verify(b"message", &signature[..], Some(b"context")));
```

`sign` is deterministic when its last argument is `None`. Pass `Some(randomness)` for the hedged variant, which FIPS 205 recommends.

Pre-hash signing (HashSLH-DSA) takes the digest of the message and the hash function that made it:

```rust
use qp_rusty_crystals_sphincs::PreHash;

let signature = keypair.secret().sign_prehash(PreHash::Sha2_512, &digest, None, None)?;
assert!(keypair.public().verify_prehash(PreHash::Sha2_512, &digest, &signature[..], None));
```

## Testing

```bash
cargo test -p qp-rusty-crystals-sphincs             # verification vectors and API tests
cargo test -p qp-rusty-crystals-sphincs --release   # adds the key generation and signing vectors
```

The crate passes all 1,248 NIST ACVP vectors for SLH-DSA: 120 keyGen, 624 sigGen and 504 sigVer cases. They cover every parameter set over the internal, pure and pre-hash interfaces. The key generation and signing vectors only run in release builds because they are slow without optimizations. `tests/acvp_vectors/update.sh` rebuilds the vector files from NIST's ACVP-Server.

## Origin and license

Apache-2.0. See [LICENSE](LICENSE).

The implementation follows [slhdsa-c](https://github.com/pq-code-package/slhdsa-c), which its authors license under Apache-2.0, ISC or MIT. slhdsa-c describes itself as work in progress and not yet recommended for production. This crate has not been audited.
