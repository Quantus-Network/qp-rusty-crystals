#!/usr/bin/env python3
"""
Quantitative key-hiding check for resharing (SECURITY_PROOF.md Open Items i-ii).

Question
--------
A new-committee adversary corrupting `t-1` parties learns all but exactly one new
RSS subset share `X_{J*}` (the hidden share whose subset is the honest set), plus
the public key and the published per-subset keys. Because it knows the other
shares, the residual instance is MLWE with secret `X_{J*}`:

    t' = t - sum_{J != J*}(A X_{J,1} + X_{J,2}) = A X_{J*,1} + X_{J*,2}.

So key hiding is governed by the *conditional* distribution of the hidden share
given the other `m-1` shares. Its per-coordinate conditional variance is the
Schur complement

    condvar = Sigma_hh - Sigma_hr Sigma_rr^{-1} Sigma_rh,    (scalar, per coord)

of the m x m covariance `Sigma` of the new subset-share vector. We compare it to
the keygen baseline.

Keygen baseline
---------------
Keygen (keygen/dealer.rs) samples each of the `m = C(n, n-t+1)` subset shares
i.i.d. `uniform_eta` = U(-eta,eta), variance v0 = eta(eta+1)/3 (2 for the eta=2
sets 44/87, 20/3 for ML-DSA-65's eta=4; select with --eta); the secret is their
sum. Being independent, the hidden share's conditional variance equals its
marginal = v0, and the induced MLWE secret is exactly the base scheme's
U(-eta,eta). So parity with keygen <=> resharing condvar >= v0 (and the
conditional law no narrower than U(-eta,eta)).

This script reproduces the *exact* v5 splitter (balanced_split_coeff +
add_mean_subtracted_noise + split_noise_params from resharing/protocol.rs),
per coordinate, for same-committee resharing, and measures condvar as a function
of the number of consecutive reshares R (to the fixed point).
"""

import argparse

import numpy as np
from math import comb

ETA = 2  # default; override with --eta 4 for ML-DSA-65


def split_noise_num_x256(s_old: int, eta: int = ETA) -> int:
    """Matches protocol.rs::split_noise_num_x256.

    eta=2: flat 125 (parity measured at every S_old). eta=4: per-committee
    numerator, calibrated as the smallest value whose fixed-point conditional
    variance is >= 1.02 * keygen variance (this script, R=20, 200k samples);
    fallback arms round down to the next calibrated S_old (more noise,
    hiding-safe).
    """
    if eta == 2:
        return 125
    if eta == 4:
        if s_old <= 2:
            return 780
        if s_old == 3:
            return 740
        if s_old == 4:
            return 700
        if s_old == 5:
            return 640
        if s_old <= 9:
            return 620
        if s_old <= 14:
            return 575
        if s_old <= 19:
            return 555
        return 550
    raise ValueError(f"unsupported ETA {eta}")


def split_noise_params(s_old: int, eta: int = ETA) -> tuple[int, int]:
    """`(threshold_per_draw, num_draws)` matching protocol.rs::split_noise_params."""
    s = max(1, s_old)
    desired = max(1, (split_noise_num_x256(s_old, eta) + s // 2) // s)
    num_draws = max(1, (desired + 126) // 127)
    t_each = min(127, max(1, (desired + num_draws // 2) // num_draws))
    return t_each, num_draws


def balanced_pieces(values, m, rng):
    """Vectorized balanced_split_coeff: split each integer in `values` (shape
    [N]) across m subsets as evenly as possible with a random rotation offset.
    Returns array [m, N] that sums to `values` along axis 0."""
    values = values.astype(np.int64)
    base = np.floor_divide(values, m)
    rem = (values - base * m).astype(np.int64)          # rem_euclid in [0, m)
    offset = rng.integers(0, m, size=values.shape[0])
    j = np.arange(m)[:, None]
    gets = (((j - offset[None, :]) % m) < rem[None, :]).astype(np.int64)
    return base[None, :] + gets


def mean_subtracted_noise(m, N, threshold, num_draws, rng):
    """Vectorized add_mean_subtracted_noise: m i.i.d. sparse-ternary deltas per
    coordinate (each the sum of `num_draws` unit draws), minus the balanced
    split of their sum. Returns [m, N], zero-sum along axis 0."""
    deltas = np.zeros((m, N), dtype=np.int64)
    for _ in range(num_draws):
        b = rng.integers(0, 256, size=(m, N))
        deltas += np.where(b < threshold, 1, np.where(b < 2 * threshold, -1, 0))
    total = deltas.sum(axis=0)
    base = np.floor_divide(total, m)
    rem = (total - base * m).astype(np.int64)
    offset = rng.integers(0, m, size=N)
    j = np.arange(m)[:, None]
    gets = (((j - offset[None, :]) % m) < rem[None, :]).astype(np.int64)
    sub = base[None, :] + gets
    return deltas - sub


def reshare_once(shares, m, threshold, num_draws, rng):
    """One same-committee reshare. `shares` is [m, N] (m old subset shares over N
    coordinate samples). Returns new [m, N]."""
    N = shares.shape[1]
    new = np.zeros((m, N), dtype=np.int64)
    for i in range(m):                      # dealer for old subset i
        new += balanced_pieces(shares[i], m, rng)
        new += mean_subtracted_noise(m, N, threshold, num_draws, rng)
    return new


def conditional_variance(cov):
    """Schur-complement conditional variance of coordinate 0 given the rest."""
    s_hh = cov[0, 0]
    s_hr = cov[0, 1:]
    s_rr = cov[1:, 1:]
    return float(s_hh - s_hr @ np.linalg.solve(s_rr, s_hr))


def run_config(t, n, reshare_counts, eta=ETA, N=400_000, seed=0xC05E7):
    m = comb(n, n - t + 1)
    thr, n_draws = split_noise_params(m, eta)
    rng = np.random.default_rng(seed)
    # keygen start: m i.i.d. U(-eta,eta) subset shares per coordinate.
    shares = rng.integers(-eta, eta + 1, size=(m, N)).astype(np.int64)

    # keygen baseline condvar (independent shares) -> should be ~v0=2.
    base_cov = np.cov(shares)
    base_cv = conditional_variance(base_cov) if m > 1 else float(base_cov)

    out = {}
    maxR = max(reshare_counts)
    for R in range(1, maxR + 1):
        shares = reshare_once(shares, m, thr, n_draws, rng)
        if R in reshare_counts:
            cov = np.cov(shares)
            cv = conditional_variance(cov) if m > 1 else float(cov)
            marg = float(np.mean(np.diag(cov)))
            out[R] = (cv, marg)
    return m, thr, base_cv, out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eta", type=int, choices=(2, 4), default=ETA,
                        help="keygen eta (2 = ML-DSA-44/87, 4 = ML-DSA-65)")
    args = parser.parse_args()
    eta = args.eta
    v0 = eta * (eta + 1) / 3.0
    configs = [(2, 2), (2, 3), (2, 4), (3, 5), (4, 6)]
    reshare_counts = [1, 2, 5, 20]
    print("Key-hiding conditional variance under v5 mean-subtracted coset resharing")
    print(f"(eta = {eta}: keygen baseline condvar = v0 = {v0:.3f}; "
          f"parity requires reshare condvar >= v0)\n")
    hdr = f"{'cfg':>5} {'m':>3} {'thr':>4} {'base_cv':>8} | " + " ".join(
        f"R={R}:cv/marg" for R in reshare_counts)
    print(hdr)
    for (t, n) in configs:
        m, thr, base_cv, out = run_config(t, n, reshare_counts, eta=eta)
        row = f"{f'{t}-{n}':>5} {m:>3} {thr:>4} {base_cv:>8.3f} | "
        cells = []
        for R in reshare_counts:
            cv, marg = out[R]
            cells.append(f"{cv:>6.3f}/{marg:>5.3f}")
        print(row + " ".join(cells))

    print("\nLegend: cv = conditional variance of hidden share given the other m-1")
    print("        marg = mean marginal variance of a new subset share")
    print(f"        sigma_cond = sqrt(cv);  keygen sigma = sqrt(v0) = {v0 ** 0.5:.3f}")


if __name__ == "__main__":
    main()
