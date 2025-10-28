# Constant-Time Testing for qp-rusty-crystals-dilithium

This project uses [dudect-bencher](https://github.com/rozbb/dudect-bencher) to test whether the Dilithium ML-DSA-87 digital signature operations execute in constant time, preventing timing side-channel attacks.

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

- **max tau < 5.0**: ✅ GOOD - No timing leakage detected
- **max tau ≥ 5.0**: ⚠️ CONCERN - Potential timing side-channel detected
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
  
- **Class B (Right)**: Random inputs  
  - Random entropy for key generation
  - Random message content for signing

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

### Statistical Analysis
The implementation uses Welch's t-test to compare timing distributions between the two input classes. The test is designed to detect even small timing differences that could be exploited by attackers.

## Security Implications

Constant-time execution is critical for Dilithium because:

1. **Key Generation**: Timing attacks could reveal information about the secret key material
2. **Signing Process**: Non-constant-time operations could leak private key bits
3. **Message Processing**: Input-dependent timing could reveal message patterns

## Development Guidelines

When modifying the Dilithium implementation:

1. **Avoid data-dependent branches**: Use conditional moves instead of if/else on secret data
2. **Consistent memory access**: Access the same memory locations regardless of secret values  
3. **Test regularly**: Run constant-time tests after any cryptographic changes
4. **Review assembly**: Check generated assembly for timing-sensitive operations

## Further Reading

- [Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems](https://www.paulkocher.com/TimingAttacks.pdf)
- [dudect: dude, is my code constant time?](https://github.com/oreparaz/dudect)
- [NIST SP 800-208: Recommendation for Stateful Hash-Based Signature Schemes](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf)