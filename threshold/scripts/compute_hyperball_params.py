#!/usr/bin/env python3
"""
Compute hyperball parameters (r, r') for threshold ML-DSA-87.

Based on the SageMath script from Threshold-ML-DSA/params/hyperball.sage
Converted to pure Python with NumPy for Monte Carlo simulation.
"""

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
    
    beta: int = field(init=False)
    sigt: float = field(init=False)
    
    def __post_init__(self):
        self.beta = self.tau * self.eta
        self.sigt = sqrt(((2 * self.eta + 1)**2 - 1) / 12)


# ML-DSA-87 parameters
Q = 8380417
PARAMS_87 = MLDSAParams(
    q=Q,
    n=256,
    k=8,
    ell=7,
    tau=60,
    eta=2,
    d=13,
    omega=75,
    gamma1=2**19,
    gamma2=(Q - 1) // 32
)

# eta parameter for rejection sampling bound
ETA_87 = 9


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


def main():
    print("=" * 70)
    print("Computing hyperball parameters for ML-DSA-87 threshold signing")
    print("=" * 70)
    
    params = PARAMS_87
    eta = ETA_87
    
    # Number of Monte Carlo samples (more = more accurate but slower)
    nbsamples = 500  # Use 2000+ for production
    
    print(f"\nUsing {nbsamples} Monte Carlo samples per configuration")
    print("(Increase for more accurate results)\n")
    
    all_results = []
    
    # Compute for N=7
    n = 7
    print(f"\n{'='*70}")
    print(f"Finding optimal parameters for N = {n}")
    print(f"{'='*70}")
    
    for t in range(2, n + 1):
        print(f"\nSearching for T={t}, N={n}...")
        result = find_params(
            t, n, eta, params,
            nbsamples=nbsamples,
            expo_range=(1.5, 12.0, 0.3),
            fact_range=(6.0, 9.0, 1.0),
            verbose=True
        )
        
        all_results.append({
            't': t,
            'n': n,
            **result
        })
        
        print(f"  Best: expo={result['expo']:.1f}, fact={result['fact']:.0f}, "
              f"r={result['r']:.0f}, r'={result['r_prime']:.0f}, K={result['k']}")
    
    # Print Rust code
    print("\n" + "=" * 70)
    print("Rust code for get_threshold_params (N=7):")
    print("=" * 70)
    for r in all_results:
        print(f"\t\t({r['t']}, {r['n']}) => Ok(({r['r']:.1f}, {r['r_prime']:.1f}, 7.0)),")
    
    # Print K values for config.rs
    print("\n" + "=" * 70)
    print("K values for k_iterations (N=7):")
    print("=" * 70)
    for r in all_results:
        print(f"  ({r['t']}, {r['n']}): K = {r['k']}")


if __name__ == "__main__":
    main()
