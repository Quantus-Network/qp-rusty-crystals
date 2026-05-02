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

```
Round 1: Blinded Reconstruction
├── Old committee members broadcast blinded contributions
└── Reconstruct secret in blinded form (never exposed in clear)

Round 2: Re-dealing  
├── Designated dealer generates fresh RSS shares
└── Distributes shares to new committee via secure channels

Round 3: Verification
├── New committee members broadcast share commitments
└── Verify all parties in same subset have consistent shares
```

## Security Properties

| Property | Guarantee |
|----------|-----------|
| **Secrecy** | Secret `s` never exposed during resharing |
| **Consistency** | All honest parties get shares of same secret |
| **Freshness** | Old shares unusable after protocol completes |
| **PK Preservation** | Public key `t = A·s1 + s2` unchanged |

## Why Custom Protocol?

Standard resharing protocols (CHURP, MPSS) assume Shamir polynomial secret sharing where shares are points on a polynomial. Our implementation uses **Replicated Secret Sharing (RSS)** with subset-indexed additive shares:

```
secret = Σ share[S]  for all subsets S containing party i
```

This structure requires a different approach:
1. Blinded reconstruction using additive homomorphism
2. Fresh RSS share generation for new subset structure
3. Commitment-based verification for consistency

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

let mut protocol = ResharingProtocol::new(config, random_seed)?;

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

## Roles

Each party has a role determined by committee membership:

| Role | Old Committee | New Committee | Actions |
|------|--------------|---------------|---------|
| `OldOnly` | ✓ | ✗ | Contribute to reconstruction |
| `NewOnly` | ✗ | ✓ | Receive and verify new shares |
| `Both` | ✓ | ✓ | Contribute + receive |

## Message Types

- `Round1Broadcast`: Blinded share contributions from old committee
- `Round2Message`: New share distributions (private, point-to-point)
- `Round3Broadcast`: Share commitments from new committee for verification

## Limitations

- Maximum 12 parties (due to u16 subset masks)
- Requires `t_old` responsive old committee members
- Secure channels required for Round 2 private messages
