# Resharing Plan for RSS-based Threshold ML-DSA-87

This document outlines the plan to implement resharing (committee handoff) for our threshold Dilithium implementation. This enables changing the participant set while preserving the same public key.

> **Created:** January 2026  
> **Status:** Planning  
> **Related:** NEAR_INTEGRATION_PLAN.md

---

## Executive Summary

Our threshold ML-DSA-87 implementation uses **Replicated Secret Sharing (RSS)**, not Shamir polynomial sharing. This means existing resharing protocols (CHURP, MPSS) cannot be directly applied. We need to implement a custom resharing protocol suited to our additive/RSS structure.

**Key Insight:** The public key `t = A·s1 + s2` is derived from the *sum* of all shares. As long as resharing preserves these sums, the public key remains unchanged.

---

## Background

### Why Resharing Matters for Production

Without resharing, Dilithium domains are "frozen" to their initial participant set:

| Scenario | Impact |
|----------|--------|
| Node operator wants to leave | Cannot replace them - must keep running forever |
| Node is compromised | Cannot exclude it from the committee |
| Want to add redundancy | Cannot add new nodes |
| TEE attestation fails | Cannot reshare to exclude bad node |

### Why Existing Protocols Don't Work

| Protocol | Based On | Why It Doesn't Fit |
|----------|----------|-------------------|
| CHURP | Shamir (polynomial) | Uses polynomial interpolation, bivariate polynomials |
| MPSS | Shamir (polynomial) | Uses blinding polynomials with roots at new node IDs |
| Threshold-ML-DSA reference | N/A | No resharing implemented at all |

Our RSS structure uses subset-indexed additive shares, not polynomial evaluations.

### Our RSS Structure

```
For (t=2, n=3) threshold:
  - Subsets of size (n-t+1) = 2: {01, 02, 12}
  - Secret: s = s_{01} + s_{02} + s_{12}
  
  Party 0 holds: {s_{01}, s_{02}}
  Party 1 holds: {s_{01}, s_{12}}
  Party 2 holds: {s_{02}, s_{12}}
  
  Any 2 parties can reconstruct s
```

In code (`keys.rs`):
```rust
struct PrivateKeyShare {
    shares: HashMap<u16, SecretShareData>,  // subset_mask → (s1_share, s2_share)
    // ...
}
```

---

## Resharing Protocol Design

### Overview

Resharing (committee handoff) consists of:

1. **Reconstruction Phase:** Threshold of old committee members reconstruct the secret (blinded)
2. **Re-dealing Phase:** Generate fresh RSS shares for new committee structure
3. **Distribution Phase:** Send new shares to new committee members
4. **Verification Phase:** New committee verifies their shares are consistent

### Why "Handoff" Instead of "Refresh"

We considered two approaches:

| Approach | Description | Pros | Cons |
|----------|-------------|------|------|
| Same-Committee Refresh | Add coordinated zero-shares locally | Efficient O(n²) | Only works for same participants |
| Committee Handoff | Reconstruct + re-deal | Handles all cases | Requires threshold cooperation |

**Decision:** Implement handoff first because:
- It's the typical NEAR MPC use case (participant changes)
- Handoff to same participants = effective refresh
- Code for refresh (zero-share coordination) is not reusable for handoff
- Can optimize with dedicated refresh protocol later if needed

### Protocol Details

#### Phase 1: Blinded Reconstruction

```
Inputs:
  - Old committee: {P_1, ..., P_n} with threshold t
  - At least t parties participate
  
Protocol:
  1. Each participating party P_i samples random blinding values:
     b_i^{s1} ← η-bounded polynomial vector
     b_i^{s2} ← η-bounded polynomial vector
     
  2. P_i computes blinded share contribution:
     For each subset S containing i:
       contribution_i[S] = share_i[S] + b_i
       
  3. Parties exchange contributions and sum to get:
     s1_blinded = s1_total + Σ b_i^{s1}
     s2_blinded = s2_total + Σ b_i^{s2}
     
  4. Store total_blinding = Σ b_i for later removal
```

**Security:** The secret is never exposed in the clear. All intermediate values are blinded.

#### Phase 2: Re-dealing for New Committee

```
Inputs:
  - New committee: {Q_1, ..., Q_m} with threshold t'
  - Blinded secret: (s1_blinded, s2_blinded)
  - Total blinding: total_blinding
  
Protocol:
  1. Compute new subset structure for (t', m):
     New subsets have size (m - t' + 1)
     
  2. Generate fresh RSS shares that sum to s1_blinded, s2_blinded:
     - Sample random shares for all but one subset
     - Compute final subset share to make sum correct
     
  3. Remove blinding from the sum:
     Adjust one share by subtracting total_blinding
     
  4. Result: Fresh RSS shares for (s1_total, s2_total)
```

#### Phase 3: Distribution

```
Protocol:
  1. For each new party Q_j:
     - Identify subsets containing Q_j
     - Send corresponding shares over secure channel (PQ-TLS)
     
  2. Each Q_j stores received shares in their PrivateKeyShare
```

#### Phase 4: Verification

```
Protocol:
  1. Each new party commits to their shares (hash-based or lattice commitment)
  
  2. Parties exchange and verify commitments are consistent:
     - Shared subsets should have matching commitments
     
  3. Optional: Test signing with new shares
```

### Noise Control

Critical for lattice-based crypto: coefficients must stay bounded.

```
Invariants to maintain:
  - All shares have coefficients in [-η, η] where η = 2 for ML-DSA-87
  - Blinding values sampled from same distribution
  - Use rejection sampling if sums exceed bounds
  
Existing code to reuse:
  - sample_poly_leq_eta() in dealer.rs
  - Rejection sampling logic from signing protocol
```

---

## Implementation Plan

### Phase 1: Core Resharing Types and Traits

**Files to create/modify:**
- `threshold/src/resharing/mod.rs` (new)
- `threshold/src/resharing/types.rs` (new)
- `threshold/src/resharing/protocol.rs` (new)

**Tasks:**
1. Define `ResharingConfig` struct:
   ```rust
   pub struct ResharingConfig {
       old_threshold: u32,
       old_participants: ParticipantList,
       new_threshold: u32,
       new_participants: ParticipantList,
   }
   ```

2. Define `ResharingProtocol` with poke/message pattern (like `DilithiumSignProtocol`)

3. Define message types:
   - `ResharingRound1` - blinded share contributions
   - `ResharingRound2` - new share distributions
   - `ResharingRound3` - verification commitments

**Estimated effort:** 1-2 days

### Phase 2: Blinded Reconstruction

**Files to modify:**
- `threshold/src/resharing/protocol.rs`
- `threshold/src/protocol/secret_sharing.rs` (add blinded reconstruction)

**Tasks:**
1. Implement blinding value generation (reuse `sample_poly_leq_eta`)
2. Implement blinded share contribution computation
3. Implement share aggregation with blinding
4. Add tests for reconstruction correctness

**Estimated effort:** 2-3 days

### Phase 3: Re-dealing for New Structure

**Files to modify:**
- `threshold/src/resharing/protocol.rs`
- `threshold/src/keygen/dealer.rs` (extract reusable logic)

**Tasks:**
1. Extract `generate_rss_shares_for_secret()` from dealer.rs
2. Implement subset structure computation for arbitrary (t, n)
3. Implement share generation with blinding removal
4. Ensure noise bounds are maintained

**Estimated effort:** 2-3 days

### Phase 4: Distribution and Verification

**Files to modify:**
- `threshold/src/resharing/protocol.rs`
- `threshold/src/resharing/verification.rs` (new)

**Tasks:**
1. Implement share distribution messages
2. Implement hash-based commitment scheme for verification
3. Implement commitment consistency checking
4. Add comprehensive tests

**Estimated effort:** 2 days

### Phase 5: NEAR MPC Integration

**Files to modify:**
- `near-mpc/crates/node/src/providers/dilithium/mod.rs`
- `near-mpc/crates/node/src/providers/dilithium/resharing.rs` (new)

**Tasks:**
1. Implement `run_key_resharing_client()` (currently returns error)
2. Create `DilithiumResharingAdapter` (like `DilithiumDkgAdapter`)
3. Integrate with NEAR's resharing state machine
4. Add integration tests

**Estimated effort:** 3-4 days

### Phase 6: Testing

**Test scenarios:**
```
1. Same participants resharing (t,n) → (t,n)
   - Validates basic correctness
   - Public key unchanged
   - New shares work for signing

2. Add one participant (t,n) → (t,n+1)
   - New party receives valid shares
   - Old parties get updated shares

3. Remove one participant (t,n) → (t,n-1)
   - Remaining parties get new shares
   - Removed party's old shares useless

4. Change threshold (t,n) → (t',n)
   - Subset structure changes
   - All parties get restructured shares

5. Complete committee change (t,n) → (t',m) with different participants
   - Most general case
   - Validates full protocol
```

**Estimated effort:** 2-3 days

---

## Security Considerations

### Threat Model

- **Honest-but-curious during resharing:** Parties follow protocol but try to learn secret
- **Threshold corruption:** Up to t-1 parties corrupted at any time
- **Mobile adversary:** Different parties corrupted before/after resharing

### Security Properties

1. **Secrecy:** Secret never exposed in clear during resharing (blinding protects it)
2. **Consistency:** All honest parties end up with shares of the same secret
3. **Freshness:** Old shares become useless after resharing completes
4. **Public key preservation:** Public key `t = A·s1 + s2` unchanged

### Secure Channels

Resharing requires secure point-to-point channels. NEAR MPC already provides PQ-TLS (post-quantum TLS), which is essential since we're protecting a post-quantum signature scheme.

---

## Open Questions

1. **Abort handling:** What if resharing fails partway through?
   - Option A: Rollback to old shares (requires not deleting until confirmed)
   - Option B: Retry with different participant set
   
2. **Async vs sync:** Should resharing be synchronous (all parties online) or support async?
   - NEAR MPC's existing resharing is effectively synchronous
   
3. **Verification strength:** Hash-based commitments vs. lattice-based proofs?
   - Hash-based is simpler and sufficient for honest-but-curious
   - Lattice proofs would handle malicious parties but add complexity

4. **Incremental handoff:** Can we support adding one party without full re-deal?
   - Potentially more efficient but adds protocol complexity
   - Defer to future optimization

---

## References

- [CHURP: Dynamic-Committee Proactive Secret Sharing](https://eprint.iacr.org/2019/017) - CCS 2019
- [MPSS: Mobile Proactive Secret Sharing](https://pmg.csail.mit.edu/papers/a34-schultz.pdf) - TISSEC 2010
- [Threshold ML-DSA paper](./papers/ThresholdMLDSA.pdf) - Celi et al.
- Our implementation: `qp-rusty-crystals/threshold/`
- NEAR MPC integration: `near-mpc/crates/node/src/providers/dilithium/`

---

## Timeline

| Phase | Description | Estimate | Dependencies |
|-------|-------------|----------|--------------|
| 1 | Core types and traits | 1-2 days | None |
| 2 | Blinded reconstruction | 2-3 days | Phase 1 |
| 3 | Re-dealing | 2-3 days | Phase 2 |
| 4 | Distribution & verification | 2 days | Phase 3 |
| 5 | NEAR MPC integration | 3-4 days | Phase 4 |
| 6 | Testing | 2-3 days | Phase 5 |

**Total estimate:** 12-18 days

---

## Changelog

- **January 2026:** Initial plan created after analysis of CHURP, MPSS, and our RSS structure