# Resharing (Committee Handoff) Protocol

This module implements resharing for threshold ML-DSA-87, allowing the participant set to change while preserving the same public key.

## Why Resharing?

In production deployments, nodes may need to:
- **Join**: New nodes added to increase availability
- **Leave**: Nodes retired or decommissioned  
- **Replace**: Compromised or failed nodes swapped out
- **Rebalance**: Change threshold (e.g., 2-of-3 → 3-of-5)

Without resharing, any change would require generating a new key and migrating all assets/contracts to the new public key.

## Protocol Overview

### Participants

- **Old Committee**: Parties holding current shares (threshold `t_old` of `n_old`)
- **New Committee**: Parties that will hold new shares (threshold `t_new` of `n_new`)
- **Overlap**: Parties may be in both committees

### Phases

This module uses **distributed per-subset re-sharing** — at no point does any
party ever assemble the full secret `s`, and at no point is any individual
share exposed in clear on the wire.

```
Round 1: Per-subset commitments
├── For each old subset I, the designated dealer D_I (lowest-ID old participant in I)
│   deterministically derives sub-shares  r_{I→J}  for every new subset J such that
│   Σ_J r_{I→J} = s_I^old   (where s_I^old is the η-bounded share that all members of
│   I already hold).
└── D_I broadcasts H(r_{I→J}) for each (I, J).  Members of I can independently
    recompute the same r_{I→J} from s_I^old and verify D_I's commitments.

Round 2: Private sub-share reveal
├── D_I privately delivers r_{I→J} to each member of new subset J.
└── No public traffic carries any share material.

Round 3: Verification + accusations + public-key invariant
├── Each new party verifies received r_{I→J} against the Round 1 commitment, then
│   sums  s_J^new = Σ_I r_{I→J}  for each new subset J they're in, and broadcasts
│   a commitment to s_J^new so that the membership of J can cross-verify.
├── Each new party also broadcasts t_J^new = A·s1_J^new + s2_J^new (mod Q) for
│   every J they hold. After Round 3, anyone can sum these and confirm
│   Σ_J t_J^new = T (the original public key). This is the only line of defense
│   against a malicious dealer that owns a *size-1* old subset (e.g. t = n
│   configurations), where there is no other I-member to cross-verify the
│   dealer's commitments. Publishing t_J^new is safe — recovering s_J^new from
│   t_J^new is the LWE problem.
└── Old subset members file DealerAccusation if any dealer's broadcast commitment
    doesn't match their independent recomputation.
```

Because `Σ_J s_J^new = Σ_J Σ_I r_{I→J} = Σ_I s_I^old = s`, the secret — and
hence the public key `t = A·s1 + s2` — is preserved.

## Security Properties

| Property | Guarantee |
|----------|-----------|
| **Secrecy of `s`** | No party — not even any dealer — ever holds `s` in clear. Each `D_I` only handles `s_I^old`, which they already had. |
| **Confidentiality of contributions** | Round 1 broadcasts only hash commitments; Round 2 sub-shares travel privately. Even an unbounded eavesdropper learns nothing about any `s_I^old` from the public transcript. |
| **Cheating-dealer detection** | Other members of `I` independently recompute `r_{I→J}` from `s_I^old` and accuse `D_I` if the broadcast commitment differs; new-subset members cross-verify computed `s_J^new`; and a final partial-public-key sum check reconstructs `T` from `Σ_J t_J^new`, catching any dealer that lied about a residual even when their old subset has size 1. |
| **PK Preservation** | Public key `t = A·s1 + s2` unchanged, verified at the end of Round 3 via a deterministic byte-equality check against the original PK. |

## Why Custom Protocol?

Standard resharing protocols (CHURP, MPSS) assume Shamir polynomial secret sharing where shares are points on a polynomial. Our implementation uses **Replicated Secret Sharing (RSS)** with subset-indexed additive shares:

```
secret = Σ share[S]  for all subsets S of size n - t + 1
```

The custom design lets each old RSS subset re-share *its own* η-bounded share
to the new committee independently, without anyone ever combining the
sub-shares back into `s`.

## Usage

```rust
use qp_rusty_crystals_threshold::resharing::{
    ResharingConfig, ResharingProtocol, Action,
};

// Configure resharing
let config = ResharingConfig::new(
    old_threshold,      // e.g., 2
    old_participants,   // e.g., vec![0, 1, 2]
    new_threshold,      // e.g., 3
    new_participants,   // e.g., vec![1, 2, 3, 4]
    my_party_id,
    my_existing_share,  // Some(share) if in old committee, None if joining
)?;

let mut protocol = ResharingProtocol::new(config);

// Run protocol loop
loop {
    match protocol.poke()? {
        Action::Wait => { /* wait for network messages */ }
        Action::SendMany(data) => { /* broadcast to all parties */ }
        Action::SendPrivate(to, data) => { /* send to specific party */ }
        Action::Return(output) => {
            // Resharing complete
            let new_share = output.private_share;
            break;
        }
    }
    
    // Process incoming messages
    for (from, data) in incoming_messages {
        protocol.message(from, data)?;
    }
}
```

## ⚠️ Transport Security Requirements

**CRITICAL**: Round 2 messages (`Action::SendPrivate`) contain secret share material in plaintext
and **MUST** be transmitted over an authenticated-encrypted channel. The protocol does not
provide its own encryption layer.

| Message Type | Transport Requirement |
|--------------|----------------------|
| `Action::SendMany` (Round 1, 3) | Authenticated broadcast (integrity only) |
| `Action::SendPrivate` (Round 2) | **Authenticated encryption required** (confidentiality + integrity) |

If `SendPrivate` messages are sent over an unencrypted channel, an eavesdropper can recover
the sub-shares `r_{I→J}` and potentially reconstruct secret key material.

**For NEAR MPC**: The existing authenticated-encryption transport satisfies this requirement.

**For other integrations**: Ensure your transport layer provides:
- Confidentiality (e.g., TLS, Noise Protocol, or application-layer encryption)
- Authentication (recipient can verify the sender's identity)
- Integrity (messages cannot be modified in transit)

## Roles

Each party has a role determined by committee membership:

| Role | Old Committee | New Committee | Actions |
|------|--------------|---------------|---------|
| `OldOnly` | ✓ | ✗ | Deal sub-shares for old subsets they own; file dealer accusations |
| `NewOnly` | ✗ | ✓ | Receive sub-shares; verify against commitments; aggregate `s_J^new` |
| `Both`    | ✓ | ✓ | Deal + receive + verify |

## Message Types

- `Round1Broadcast`: per-subset commitment hashes  `H(r_{I→J})`  (no plaintext shares)
- `Round2Message`: private sub-share reveal (**requires secure channel** — see Transport Security above) — one message per (dealer, recipient) carrying every `r_{I→J}` the dealer owes that recipient. Dealers handle self-deals locally and never emit `SendPrivate(self, _)`.
- `Round3Broadcast`: commitments to computed `s_J^new`, partial public-key contributions `t_J^new`, and any `DealerAccusation`s

## Limitations

- Maximum 16 parties (due to u16 subset masks)
- Requires every designated dealer to be online; if a dealer is offline or
  cheats, the protocol aborts (no recovery / re-deal in this implementation)
- **Secure channels required for Round 2 private messages** (see Transport Security section above)
