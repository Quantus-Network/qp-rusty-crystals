#!/usr/bin/env python3
"""
Compute hyperball parameters (r, r') for threshold ML-DSA.

Based on the SageMath script from Threshold-ML-DSA/params/hyperball.sage
Converted to pure Python with NumPy for Monte Carlo simulation.

Usage:
  python compute_hyperball_params.py              # ML-DSA-87 (default)
  python compute_hyperball_params.py --variant 44
  python compute_hyperball_params.py --variant 65
  python compute_hyperball_params.py --variant 87 --nbsamples 400
"""

import argparse
import numpy as np
from math import comb, sqrt, ceil, log
from dataclasses import dataclass, field
import random
from typing import Callable
import sys


@dataclass
class MLDSAParams:
    """ML-DSA parameter set."""
    q: int
    n: int  # polynomial degree
    k: int  # number of polynomials in t/w
    ell: int  # number of polynomials in s1/y
    tau: int  # number of ±1 in challenge
    eta: int  # secret key coefficient bound
    d: int  # dropped bits from t
    omega: int  # max hint weight
    gamma1: int
    gamma2: int
    name: str = "ML-DSA"
    
    beta: int = field(init=False)
    sigt: float = field(init=False)
    
    def __post_init__(self):
        self.beta = self.tau * self.eta
        self.sigt = sqrt(((2 * self.eta + 1)**2 - 1) / 12)


Q = 8380417
PARAMS_44 = MLDSAParams(
    q=Q, n=256, k=4, ell=4, tau=39, eta=2, d=13, omega=80,
    gamma1=2**17, gamma2=(Q - 1) // 88, name="ML-DSA-44",
)
PARAMS_65 = MLDSAParams(
    q=Q, n=256, k=6, ell=5, tau=49, eta=4, d=13, omega=55,
    gamma1=2**19, gamma2=(Q - 1) // 32, name="ML-DSA-65",
)
PARAMS_87 = MLDSAParams(
    q=Q, n=256, k=8, ell=7, tau=60, eta=2, d=13, omega=75,
    gamma1=2**19, gamma2=(Q - 1) // 32, name="ML-DSA-87",
)

# Rejection-sampling eta (script parameter; distinct from secret-key η).
ETA_RS = {44: 6, 65: 8, 87: 9}
FACT_DEFAULT = {44: 6.0, 65: 7.0, 87: 7.0}
VARIANT_PARAMS = {44: PARAMS_44, 65: PARAMS_65, 87: PARAMS_87}

# Backward-compatible aliases
ETA_87 = ETA_RS[87]


def sample_ball_imbalanced(radius: float, fact: float, params: MLDSAParams) -> tuple[np.ndarray, np.ndarray]:
    """
    Sample uniformly from a hyperball with imbalanced scaling.
    
    The s1 part is scaled by `fact` relative to s2.
    """
    dim = (params.k + params.ell) * params.n
    x = np.random.normal(size=dim + 2)
    s = np.linalg.norm(x)
    ratio = radius / s
    res = ratio * x[:-2]
    
    s1_part = res[:params.ell * params.n] * fact
    s2_part = res[params.ell * params.n:]
    return s1_part, s2_part


def sample_ball_int(radius: float, fact: float, params: MLDSAParams) -> tuple[np.ndarray, np.ndarray]:
    """Sample from hyperball and round to integers."""
    s1, s2 = sample_ball_imbalanced(radius, fact, params)
    return np.rint(s1).astype(np.int64), np.rint(s2).astype(np.int64)


def sample_t_parties(t: int, radius: float, fact: float, params: MLDSAParams) -> tuple[np.ndarray, np.ndarray]:
    """
    Sample the sum of T independent hyperball samples.
    
    This simulates what happens when T parties each contribute a random sample.
    """
    v1 = np.zeros(params.ell * params.n, dtype=np.int64)
    v2 = np.zeros(params.k * params.n, dtype=np.int64)
    
    for _ in range(t):
        s1, s2 = sample_ball_int(radius, fact, params)
        v1 += s1
        v2 += s2
    
    return v1, v2


def highbits(r: int, alpha: int, q: int) -> int:
    """Compute HighBits(r, alpha) as in ML-DSA."""
    r = r % q
    r0 = r % alpha
    if r0 > alpha // 2:
        r0 -= alpha
    if r - r0 == q - 1:
        return 0
    return (r - r0) // alpha


def make_hint(z: int, r: int, alpha: int, q: int) -> int:
    """Compute MakeHint(z, r, alpha) as in ML-DSA."""
    r1 = highbits(r, alpha, q)
    v1 = highbits(r + z, alpha, q)
    return int(r1 != v1)


def poly_mul_mod(a: np.ndarray, b: np.ndarray, n: int = 256) -> np.ndarray:
    """
    Multiply two polynomials mod X^n + 1.
    
    Uses convolution and reduction.
    """
    # Full convolution
    c = np.convolve(a, b)
    # Reduce mod X^n + 1: coefficients at degree >= n get subtracted from degree - n
    result = np.zeros(n, dtype=np.int64)
    for i, coef in enumerate(c):
        idx = i % n
        sign = 1 if (i // n) % 2 == 0 else -1
        result[idx] += sign * coef
    return result


def evaluate_proba_success(
    sampler: Callable[[], tuple[np.ndarray, np.ndarray]],
    nbsamples: int,
    params: MLDSAParams
) -> dict[str, float]:
    """
    Evaluate the probability of success for rejection sampling.
    
    Uses Monte Carlo simulation to estimate:
    1. P(||z_1||_∞ < γ1 - β) - the s1 part passes norm check
    2. P(||r_2 - c·t_0||_∞ ≤ γ2) - the s2 part passes norm check  
    3. P(|hint| ≤ ω) - hint weight is acceptable
    """
    check_r1 = 0
    check_r2 = 0
    check_hint = 0
    
    alpha = 2 * params.gamma2
    
    for _ in range(nbsamples):
        # Sample the signing randomness
        r1, r2 = sampler()
        
        # Check 1: ||r1||_∞ < γ1 - β
        norm_inf_r1 = np.max(np.abs(r1))
        if norm_inf_r1 < params.gamma1 - params.beta:
            check_r1 += 1
        
        # Sample a random challenge c (sparse polynomial with τ coefficients ±1)
        c_coeffs = np.zeros(params.n, dtype=np.int64)
        positions = random.sample(range(params.n), params.tau)
        for pos in positions:
            c_coeffs[pos] = random.choice([-1, 1])
        
        # Sample random t0 (lower bits of public key)
        t0_bound = 2 ** (params.d - 1)
        
        # Sample random w (commitment, uniformly distributed mod q)
        # We compute the hint based on v = r2 - c*t0
        
        total_hints = 0
        max_norm_v = 0
        
        # Process each polynomial in r2
        for j in range(params.k):
            r2_j = r2[j * params.n:(j + 1) * params.n]
            t0_j = np.random.randint(-t0_bound, t0_bound, size=params.n, dtype=np.int64)
            w_j = np.random.randint(0, params.q, size=params.n, dtype=np.int64)
            
            # v = r2 - c * t0 mod (X^n + 1)
            ct0 = poly_mul_mod(c_coeffs, t0_j, params.n)
            v_j = r2_j - ct0
            
            # Check norm
            max_norm_v = max(max_norm_v, np.max(np.abs(v_j)))
            
            # Compute hints
            for i in range(params.n):
                total_hints += make_hint(int(v_j[i]), int(w_j[i]), alpha, params.q)
        
        # Check 2: ||v||_∞ ≤ γ2
        if max_norm_v <= params.gamma2:
            check_r2 += 1
        
        # Check 3: hint weight ≤ ω
        if total_hints <= params.omega:
            check_hint += 1
    
    return {
        "checknorminf_r1": check_r1 / nbsamples,
        "checknorminf_r2mcto": check_r2 / nbsamples,
        "checkhint": check_hint / nbsamples,
    }


def compute_radii(t: int, n: int, expo: float, fact: float, eta: int, params: MLDSAParams) -> tuple[float, float]:
    """
    Compute rejection sampling radii (r, r') for threshold (t, n).
    """
    dim = (params.k + params.ell) * params.n
    
    p_accept = 1.0 / (2 ** expo)
    M = (1.0 / p_accept) ** (1.0 / t)
    
    M_exp = M ** (2.0 / dim)
    slack = (1.0/eta + sqrt(1.0/(eta**2) + M_exp - 1)) / (M_exp - 1)
    slackradius2 = M ** (1.0 / dim)
    
    num_subsets = ceil(comb(n, t - 1) / t)
    beta = 1.3 * sqrt((params.k + params.ell / (fact**2)) * params.n * num_subsets) * params.sigt * sqrt(params.tau)
    
    radius = slack * beta
    radius2 = slackradius2 * radius
    
    return radius, radius2


def find_params(
    t: int,
    n: int,
    eta: int,
    params: MLDSAParams,
    nbsamples: int = 1000,
    expo_range: tuple[float, float, float] = (1.5, 10.0, 0.5),
    fact_range: tuple[float, float, float] = (6.0, 9.0, 1.0),
    verbose: bool = False
) -> dict:
    """
    Find optimal parameters for threshold (t, n) through grid search.
    
    Returns the parameters that maximize acceptance probability.
    """
    best = {
        'expo': 0,
        'fact': 0,
        'p_final': 0,
        'r': 0,
        'r_prime': 0,
        'k': 0,
        'probas': None
    }
    
    expo_min, expo_max, expo_step = expo_range
    fact_min, fact_max, fact_step = fact_range
    
    expo = expo_min
    while expo <= expo_max:
        fact = fact_min
        while fact <= fact_max:
            p_accept = 1.0 / (2 ** expo)
            r, r_prime = compute_radii(t, n, expo, fact, eta, params)
            
            # Monte Carlo evaluation
            sampler = lambda r=r, f=fact: sample_t_parties(t, r, f, params)
            probas = evaluate_proba_success(sampler, nbsamples, params)
            
            p_final = p_accept * probas["checknorminf_r1"] * probas["checknorminf_r2mcto"] * probas["checkhint"]
            
            if p_final > best['p_final']:
                k = ceil(-1 / log(1 - p_final, 2)) if p_final > 0 and p_final < 1 else 9999
                best = {
                    'expo': expo,
                    'fact': fact,
                    'p_final': p_final,
                    'r': r,
                    'r_prime': r_prime,
                    'k': k,
                    'probas': probas
                }
                if verbose:
                    print(f"  ({t},{n}) expo={expo:.1f} fact={fact:.0f}: p={p_final:.4f} r={r:.0f} K={k}")
            
            fact += fact_step
        expo += expo_step
    
    return best


def beta_bound(t: int, n: int, fact: float, params: MLDSAParams) -> float:
    """The partial-secret norm bound B (== `beta` in compute_radii)."""
    num_subsets = ceil(comb(n, t - 1) / t)
    return 1.3 * sqrt((params.k + params.ell / (fact**2)) * params.n * num_subsets) * params.sigt * sqrt(params.tau)


def recover_expo(t: int, n: int, fact: float, eta: int, params: MLDSAParams, r_target: float) -> float:
    """Recover the reference `expo` (fact fixed) by matching the reference r."""
    best = None
    e = 1.5
    while e <= 25.0:
        r, _ = compute_radii(t, n, e, fact, eta, params)
        d = abs(r - r_target)
        if best is None or d < best[0]:
            best = (d, e)
        e += 0.005
    return best[1]


# Per-variant resharing calibration inputs. `ref_r` are the *base* (kappa=1)
# radii for each config; `overshoot` is the measured max honest-reshare
# overshoot sqrt(tau)*||p||_nu / B_base at the repeated-reshare fixed point
# (Rust test_recovered_partial_variance_*: 100 reshares for (2,*), 20 for
# (3,5), 10 for (4,6); max over all signing sets), built with the variant's
# cargo feature. ML-DSA-65 is intentionally absent: eta=4 keygen variance
# (20/3) dwarfs the eta=2-tuned split noise, so its measured overshoots are
# 0.62-0.92 (< 1 everywhere) and it reshares at kappa=1 with base tables.
RESHARING_DATA = {
    87: dict(
        fact=7.0,
        ref_r={(2, 2): 503119.0, (2, 3): 631601.0, (2, 4): 632903.0,
               (3, 5): 577400.0, (4, 6): 517689.0},
        overshoot={(2, 2): 0.780, (2, 3): 0.810, (2, 4): 0.961,
                   (3, 5): 1.012, (4, 6): 1.163},
        kappa={(2, 2): 1.00, (2, 3): 1.00, (2, 4): 1.10, (3, 5): 1.15, (4, 6): 1.25},
        ship_k={(2, 2): 4, (2, 3): 5, (2, 4): 10, (3, 5): 60, (4, 6): 1600},
    ),
    44: dict(
        fact=6.0,
        ref_r={(2, 2): 164656.6, (2, 3): 175209.0, (2, 4): 175209.0,
               (3, 5): 149931.1, (4, 6): 140270.0},
        overshoot={(2, 2): 0.794, (2, 3): 0.827, (2, 4): 0.991,
                   (3, 5): 1.023, (4, 6): 1.166},
        # Same enlargements as ML-DSA-87: the measured overshoots are nearly
        # identical (the splitter overshoot is a variance ratio, largely
        # independent of the parameter set), giving ~7-11% margins.
        kappa={(2, 2): 1.00, (2, 3): 1.00, (2, 4): 1.10, (3, 5): 1.15, (4, 6): 1.25},
    ),
}


def compute_resharing_params(variant: int, nbsamples: int = 8000):
    """
    Enlarged hyperball params for resharing support.

    Honest resharing inflates recovered-partial norms past the keygen bound B by a
    factor (the `OVERSHOOT` below). The v5 mean-subtracted "coset" splitter
    (sparse-ternary deltas scaled as 1/S_old minus their balanced mean; see
    resharing/protocol.rs add_mean_subtracted_noise) holds that overshoot at
    ~0.78-1.16x for every committee 2<=T<=N<=6, instead of the ~sqrt(S_old) growth
    of the old fixed-CBD splitter (which gave (3,5): 2.61x, (4,6): 4.50x). Its
    uniform negative correlation also beats the v4 telescoping cycle (which overshot
    on non-contiguous recovery patterns: 4-of-6 ~1.29x vs ~1.16x here).

    To accept honest reshares we enlarge B -> kappa*B AND the radii
    (r, r') -> (kappa*r, kappa*r') together. Scaling (B, r, r') by a common kappa
    is scale-invariant in the radius condition r'^2 = r^2 + B^2 + 2 r B / phi, so
    the per-sample leakage eps is left unchanged. The query budget Q_s = 1/(K*eps)
    is NOT preserved, though: K grows (the enlarged radius nears ML-DSA's fixed
    verification ceilings), and with eps fixed Q_s falls by that same K factor
    (e.g. (3,5) K 35->60 costs ~0.8 bits; (4,6) K 350->1600 costs ~2.2 bits). This
    is feasible only while the enlarged radius stays under ML-DSA-87's verification
    ceiling (||z1||_inf < gamma1 - beta), which caps kappa at ~1.5x.

    (2,2)/(2,3) overshoot below 1 so they reshare at kappa=1 (base signing params,
    no Q_s cost); (2,4)/(3,5) take kappa=1.10/1.15. (4,6) (overshoot ~1.16x, stable
    across seeds) is enabled by enlargement at kappa=1.25 => K=1600 for the near-mpc
    4-of-6 shape. The path back to kappa=1/K=350 (budgeted per-reshare noise
    intensity, or a collaborative coset-Gaussian sample) is future work.

    Per-variant data (`RESHARING_DATA`): the reference radii are the *base*
    (kappa=1) radii for each config; the overshoots are measured by the Rust
    `test_recovered_partial_variance_*` tests built with that variant's feature.
    ML-DSA-65 measures below 1 everywhere (eta=4 keygen variance dwarfs the
    eta=2-tuned split noise), so it reshares at kappa=1 and needs no enlargement.
    """
    if variant not in RESHARING_DATA:
        print(f"\nML-DSA-{variant}: no resharing enlargement needed "
              f"(measured overshoot < 1 for all supported committees; kappa = 1).")
        return
    data = RESHARING_DATA[variant]
    params = VARIANT_PARAMS[variant]
    eta = ETA_RS[variant]
    fact = data["fact"]
    REF_R = data["ref_r"]
    OVERSHOOT = data["overshoot"]
    KAPPA = data["kappa"]
    SHIP_K = data.get("ship_k")

    print("\n" + "=" * 70)
    print(f"Resharing-enlarged hyperball params (ML-DSA-{variant}, v5 mean-subtracted coset splitter)")
    print("=" * 70)
    # SHIP_K: K actually shipped in params tables (87). The MC K below is a noisy
    # lower-bound estimate (it targets ~50% per-attempt success, K =
    # ceil(-1/log2(1-p))); shipped K carries completeness margin above it
    # (2x MC for the 44/65 tables).
    header = f"{'cfg':>6} {'overshoot':>9} {'kappa':>6} {'B_prime':>8} {'r':>9} {'r_prime':>9} {'K_mc':>5} {'K_2x':>5}"
    if SHIP_K:
        header += f" {'K_ship':>7}"
    print(header)
    for cfg in sorted(KAPPA):
        t, n = cfg
        expo = recover_expo(t, n, fact, eta, params, REF_R[cfg])
        k = KAPPA[cfg]
        r0, rp0 = compute_radii(t, n, expo, fact, eta, params)
        r, rp = r0 * k, rp0 * k
        p_accept = 1.0 / (2 ** expo)
        pr = evaluate_proba_success(lambda r=r: sample_t_parties(t, r, fact, params), nbsamples, params)
        p_final = p_accept * pr["checknorminf_r1"] * pr["checknorminf_r2mcto"] * pr["checkhint"]
        K = ceil(-1 / log(1 - p_final, 2)) if 0 < p_final < 1 else (1 if p_final >= 1 else 9999)
        B = beta_bound(t, n, fact, params) * k
        line = (f"{f'{t}-{n}':>6} {OVERSHOOT[cfg]:>9.2f} {k:>6.2f} {B:>8.0f} "
                f"{r:>9.0f} {rp:>9.0f} {K:>5} {2 * K:>5}")
        if SHIP_K:
            line += f" {SHIP_K[cfg]:>7}"
        print(line)


def emit_rust_tables(variant: int, results: list[dict], default_fact: float):
    """Print tables suitable for params_tables_{variant}.rs."""
    print("\n" + "=" * 70)
    print(f"// Auto-generated hyperball tables for ML-DSA-{variant}")
    print("pub(super) const K_ITERATIONS: &[(u32, u32, u32)] = &[")
    for r in results:
        # 2x MC margin (same convention used for provisional 44/65 tables)
        k = max(1, int(ceil(2 * r["k"]))) if r["k"] < 9999 else 9999
        print(f"\t({r['t']}, {r['n']}, {k}),")
    print("];")
    print()
    print("pub(super) const HYPERBALL: &[(u32, u32, f64, f64, f64)] = &[")
    for r in results:
        fact = r["fact"] if r["fact"] else default_fact
        print(f"\t({r['t']}, {r['n']}, {r['r']:.1f}, {r['r_prime']:.1f}, {fact:.1f}),")
    print("];")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", type=int, choices=sorted(VARIANT_PARAMS), default=87)
    parser.add_argument("--nbsamples", type=int, default=400,
                        help="Monte Carlo samples per (t,n) (default 400)")
    parser.add_argument("--n-max", type=int, default=6,
                        help="Max n for (t,n) grid (default 6)")
    parser.add_argument("--resharing", action="store_true",
                        help="Also print the variant's resharing-enlarged params")
    parser.add_argument("--resharing-only", action="store_true",
                        help="Skip the base grid search; only compute the "
                             "variant's resharing-enlarged params")
    args = parser.parse_args()

    params = VARIANT_PARAMS[args.variant]
    eta = ETA_RS[args.variant]
    fact0 = FACT_DEFAULT[args.variant]

    if args.resharing_only:
        compute_resharing_params(args.variant, nbsamples=max(args.nbsamples, 8000))
        return

    print("=" * 70)
    print(f"Computing hyperball parameters for {params.name} threshold signing")
    print("=" * 70)
    print(f"\nUsing {args.nbsamples} Monte Carlo samples per configuration")
    print("(Increase --nbsamples for more accurate results)\n")

    all_results = []
    for n in range(2, args.n_max + 1):
        print(f"\n{'='*70}")
        print(f"Finding optimal parameters for N = {n}")
        print(f"{'='*70}")
        for t in range(2, n + 1):
            print(f"\nSearching for T={t}, N={n}...")
            result = find_params(
                t, n, eta, params,
                nbsamples=args.nbsamples,
                expo_range=(1.5, 12.0, 0.3),
                fact_range=(max(5.0, fact0 - 1.0), fact0 + 2.0, 1.0),
                verbose=True,
            )
            all_results.append({"t": t, "n": n, **result})
            print(
                f"  Best: expo={result['expo']:.1f}, fact={result['fact']:.0f}, "
                f"r={result['r']:.0f}, r'={result['r_prime']:.0f}, K={result['k']}"
            )

    emit_rust_tables(args.variant, all_results, fact0)

    if args.resharing:
        compute_resharing_params(args.variant, nbsamples=max(args.nbsamples, 8000))


if __name__ == "__main__":
    main()
