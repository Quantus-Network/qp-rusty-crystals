# Constant-Time Testing for qp-rusty-crystals-dilithium

This project uses [dudect-bencher](https://github.com/rozbb/dudect-bencher) to test whether the Dilithium ML-DSA-87 digital signature and key generation operations execute in constant time, resisting timing side-channel attacks.

## Quick Start

Run all constant-time tests:

```bash
cd dilithium
cargo run --release --features ct-testing --bin ct_bench
```

## Understanding Results

Each test shows output like:
```
test_keypair_generation_ct        : n == +0.005M, max t = +1.83452, max tau = +0.08201, (5/tau)^2 = 3715
```

- **n**: Number of measurements taken (in millions)
- **max t**: Raw t-statistic from Welch's t-test
- **max tau**: Normalized t-statistic (more reliable for large sample sizes)
- **(5/tau)²**: Detection threshold - higher numbers are BETTER

### Interpretation Guidelines

- **|max t| < 5.0**: ✅ GOOD - No timing leakage detected
- **|max tau| < 0.1**: ✅ GOOD - No timing leakage detected
- **|max tau| ≥ 0.1**: ⚠️ CONCERN - Potential timing side-channel detected
- **Higher (5/tau)² values**: Better security - indicates more measurements would be needed to detect any leakage

## Tests Included

### Key Generation
- `test_keypair_generation_ct` - Tests ML-DSA-87 keypair generation with different entropy sources

### Signing Operations  
- `test_signing_small_ct` - Small messages (32 bytes)
- `test_signing_medium_ct` - Medium messages (256 bytes)  
- `test_signing_large_ct` - Large messages (1KB)
- `test_signing_xlarge_ct` - Extra large messages (4KB)

### Advanced Signing Modes
- `test_hedged_signing_small_ct` - Randomized (hedged) signing mode
- `test_signing_with_context_ct` - Signing with context strings
- `test_edge_cases_ct` - Single-byte and small message edge cases

## Test Methodology

The tests use a two-class approach to detect timing differences:

- **Class A (Left)**: Fixed, deterministic inputs
  - Fixed seeds for key generation
  - Fixed message patterns for signing
  - Fixed keys for signing
  
- **Class B (Right)**: Random inputs  
  - Random entropy for key generation
  - Random message content for signing
  - Random keys for signing

This ensures the input classes are statistically distinguishable before timing analysis begins.

## Best Practices

### System Setup
- **Use release builds**: Always run with `--release` for accurate timing
- **Idle system**: Close other applications during testing
- **Stable environment**: Run on a system with consistent performance
- **Multiple runs**: Execute tests multiple times to confirm results

### Troubleshooting Noisy Results
If you see inconsistent results:

1. **Check system load**: Ensure CPU is not under heavy load
2. **Disable frequency scaling**: Set CPU governor to 'performance' mode
3. **Increase sample size**: Modify iteration counts in the test functions
4. **Run longer**: Let tests run for more iterations

### Example: Disabling CPU Frequency Scaling (Linux)
```bash
# Set all CPUs to performance mode
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Run tests
cargo run --release --features ct-testing --bin ct_bench

# Restore power saving mode
echo powersave | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

## Implementation Details

### Cache Disruption
Each measurement includes cache disruption to prevent microarchitectural state from affecting subsequent measurements:

- Large memory allocation (8MB) to evict cache lines
- Random memory access patterns to disrupt prefetchers
- Memory barriers and dummy computations

This makes the tests more realistic as a real world user will not typically sign thousands of messages in a row without doing something else. 

### Statistical Analysis

The implementation uses Welch's t-test to compare timing distributions between the two input classes. The test is designed to detect even small timing differences that could be exploited by attackers.

### Implementation Strategy

Broadly speaking, we have made the rejection sampling "lumpy", in that a fixed size batch of samples is processed at a time, regardless of which of them satisfy the condition. This approach also allows us to tune the tradeoff of performance to constant-timeness. Those wishing to squeeze more performance out of the library for signing may set MAX_SIGNING_ATTEMPTS to a lower value, like 1, which reduces the amount of extra work done.

## Security Implications

Constant-time execution may not be critical for Dilithium due to the rejection sampling and the liberal use of hash functions in the algorithm. Nevertheless, we have chosen to implement constant-time operations for keygen and signing as an extra layer of protection for those who desire it. We note that adding a hedge to signing was specifically added by NIST to account for fault injection attacks. 

1. **Key Generation**: Timing attacks could reveal information about the secret key material
2. **Signing Process**: Non-constant-time operations could leak private key bits

## Further Reading

- [Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems](https://www.paulkocher.com/doc/TimingAttacks.pdf)
- [dudect: dude, is my code constant time?](https://github.com/oreparaz/dudect)
- [Extracting Trezor's Private Key with $80 Oscilloscope](https://jochen-hoenicke.de/crypto/trezor-power-analysis/)