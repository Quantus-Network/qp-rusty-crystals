#!/usr/bin/env python3
"""
Lattice-estimator pass for resharing key hiding (SECURITY_PROOF.md Open Item ii).

The new-committee key-recovery instance is module-LWE with the *same* ring,
module shape, modulus and sample count as base ML-DSA-87 (q = 8380417, n = 256,
(k, l) = (8, 7)); the only thing resharing changes is the secret/error width:
from base U(-2,2) (sigma = sqrt(2)) to the hidden share's conditional law with
per-coordinate standard deviation sigma_cond = sqrt(condvar) measured by
keyhiding_conditional.py.

We run the standard primal-uSVP "2016" core-SVP estimate (the same model used in
the Kyber/Dilithium specs) for the base width and for each config's sigma_cond,
and report BKZ block size beta and classical/quantum core-SVP bits. Because the
instance is otherwise identical, the comparison base-vs-reshared is exactly the
effect of the secret width and is robust even where the absolute estimate is
approximate; we validate the model first by reproducing Dilithium-5's published
key-recovery hardness.
"""

from math import log, sqrt, pi, e, comb

Q = 8380417
N = 256
K_DIM, L_DIM = 8, 7
# Key-recovery MLWE as LWE: secret = s1 (l*256 coords), samples = s2 rows (k*256),
# both secret and error i.i.d. with the share width.
N_SECRET = L_DIM * N         # 1792
M_MAX = K_DIM * N            # 2048


def delta_bkz(beta: int) -> float:
    return ((pi * beta) ** (1.0 / beta) * beta / (2 * pi * e)) ** (1.0 / (2 * (beta - 1)))


def primal_coresvp(sigma: float, n_secret: int = N_SECRET, m_max: int = M_MAX,
                   q: int = Q) -> tuple[int, int]:
    """Minimal BKZ block size beta for the primal-uSVP attack, optimized over the
    number of LWE samples m. Returns (beta, m*). Standard 2016 uSVP condition with
    Kannan embedding dimension d = n + m + 1:
        sigma * sqrt(beta) <= delta(beta)^(2 beta - d - 1) * q^(m / d).
    """
    best = None
    for beta in range(50, 1400):
        d_b = delta_bkz(beta)
        lhs = sigma * sqrt(beta)
        # optimize sample count m
        for m in range(max(1, n_secret // 2), m_max + 1, 8):
            d = n_secret + m + 1
            rhs = d_b ** (2 * beta - d - 1) * q ** (m / d)
            if lhs <= rhs:
                if best is None or beta < best[0]:
                    best = (beta, m)
                break
        if best is not None:
            break
    return best if best else (9999, 0)


def bits(beta: int) -> tuple[float, float]:
    return 0.292 * beta, 0.265 * beta   # classical, quantum core-SVP


def main():
    sigma_base = sqrt(2.0)

    # 1) validate against base ML-DSA-87 (Dilithium-5) key recovery.
    beta0, m0 = primal_coresvp(sigma_base)
    c0, qb0 = bits(beta0)
    print("Primal core-SVP estimate (validation)")
    print(f"  base ML-DSA-87  sigma={sigma_base:.4f}  beta={beta0}  m*={m0}  "
          f"classical={c0:.0f}b  quantum={qb0:.0f}b")
    print("  (Dilithium-5 published key-recovery core-SVP ~ classical 252b / quantum 229b)\n")

    # 2) per-config conditional variances measured by keyhiding_conditional.py
    #    (R=20 fixed point).
    condvar = {(2, 2): 1.992, (2, 3): 2.144, (2, 4): 2.237, (3, 5): 2.503, (4, 6): 2.481}

    print("Reshared hidden-share key recovery (induced MLWE, identical module shape)")
    print(f"{'cfg':>5} {'condvar':>8} {'sigma_cond':>10} {'beta':>5} {'classical':>10} {'quantum':>8} {'vs base':>9}")
    for cfg in [(2, 2), (2, 3), (2, 4), (3, 5), (4, 6)]:
        cv = condvar[cfg]
        sc = sqrt(cv)
        beta, m = primal_coresvp(sc)
        c, qb = bits(beta)
        print(f"{f'{cfg[0]}-{cfg[1]}':>5} {cv:>8.3f} {sc:>10.4f} {beta:>5} "
              f"{c:>9.0f}b {qb:>7.0f}b {c - c0:>+8.1f}b")

    print("\nbeta is monotonically non-decreasing in the secret/error width, so")
    print("sigma_cond >= sqrt(2) => key-recovery hardness >= base ML-DSA-87 (Category 5).")


if __name__ == "__main__":
    main()
