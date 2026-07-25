# Security review round 4: secret hygiene, bounded deserialization, and protocol atomicity

This PR addresses the fourth round of security review findings across the `dilithium`, `hdwallet`, and `threshold` crates. Every fix follows the same discipline: the finding was first reproduced with a failing regression test, then fixed, then re-verified (test red on the old code, green with the fix). 19 commits, 28 files, ~2600 insertions.

## Secret hygiene (zeroization)

**Heap intermediates are wiped before their memory is freed.** A new `threshold/tests/heap_zeroization.rs` suite installs a scanning global allocator that inspects every freed block for the scenario's secret pattern at `dealloc` time. It caught, and now guards, six scenarios:

- `derive_dkg_contribution`'s share-digest linearization buffer, incoming DKG Round 1 private frames carrying K_S, and the hyperball sampling scratch buffer (`7d63cf9`);
- the resharing protocol's `party_key` derivation buffer, Round 4 transport frames (both directions — `Action::SendPrivate` now carries `Zeroizing<Vec<u8>>`), sub-share derivation output, and per-polynomial hashing scratch buffers (`ce8175f`);
- DKG K_S relocation out of Copy-typed containers: `transition_to_round2` freed the `received_shared_secrets` map nodes with the secrets still in them (the state zeroizer runs too late — the field is already `None`), `pending_privates.pop()` left queued `Round1Private` bytes beyond the `Vec`'s shrunken length, and the buffered-privates drain consumed its map the same way (`4e6cb6d`);
- the wormhole Poseidon preimage (`preimage_felts`) was `clear()`ed but never wiped; covered by a dedicated allocator-instrumented test in `hdwallet/tests/wormhole_zeroization.rs` (`7d63cf9`).

**Stack copies of the ML-DSA-87 secret key are wiped in import/serialize paths.** `Keypair::from_bytes`, `SecretKey::from_bytes`, and `Keypair::to_bytes` left plaintext `[u8; SECRETKEYBYTES]` copies in dead stack frames because `[u8; N]` is `Copy`. All three now stage the secret in `Zeroizing` locals, and the secret-bearing `to_bytes` methods return `Zeroizing<[u8; N]>` so the caller's copy self-wipes too (semver-breaking; a caller who simply drops the result leaks nothing). A painted-stack probe test (`dilithium/tests/import_stack_zeroization.rs`, release-mode only — debug builds create compiler temporaries no source fix can wipe) verifies no copy survives, and CI runs it in release mode with a zero-tests-ran guard.

Known residual: the DKG private-send path (`pop_pending_private` → `poke` → `serialize_round1_private`) moves a `Round1Private` by value, and intermediate move temporaries holding K_S in dead stack frames are compiler-managed — the same class the dilithium probe pins. Heap copies on that path are covered; the stack side is noted in the code as follow-up.

**Debug output no longer leaks key material.** The resharing `Action::SendPrivate` payload (serialized sub-shares) is redacted from the manual `Debug` impl (`df8dee3`).

## Bounded, validating deserialization

- `ResharingActProposal::active_set` length is bounded at deserialize; a hostile length prefix can no longer drive unbounded allocation (`62f736e`).
- `PrivateKeyShare` metadata (threshold, party counts, participant list, share-map shape) is cross-checked at Borsh import and at `ThresholdSigner` construction (`345c7aa`).
- ML-DSA-87 secret keys whose `s1`/`s2` coefficients decode outside `[-ETA, ETA]` are rejected at import: `eta_unpack` and `unpack_sk` now return a canonicality flag (`#[must_use]`) that `public_key_from_secret` enforces, so non-canonical 3-bit slots (5–7) can no longer cross the boundary (`19e2bf0`).
- `SubsetContribution` (exported, previously derive-deserialized into unbounded `Vec<[i32; N]>`) now has a manual deserializer enforcing exactly `L`/`K` polynomials — length prefix checked before any allocation — and η-bounded coefficients, mirroring `SecretShareData` (`3ec5b15`).
- Invalid `DkgConfig` values are unconstructible: fields are private with accessors, and `all_broadcasts_received` uses total quorum arithmetic that cannot underflow on an empty participant list (`e1df0ca`). The predicate is now `pub(crate)` (no longer re-exported): its empty-list-is-complete reading is only sound for config-validated participant lists, so raw external inputs can no longer reach it — pinned by a `compile_fail` doctest on `DkgConfig`.

## DoS hardening (no work before validation)

- The signing protocol checks the fixed-header SSID and a **per-config** frame budget (`k_iterations`-derived, ~23 KB for a (2,2) session instead of the global 12 MiB) before deserializing anything (`0428526`).
- `ExtendedPrivKey::derive` parses and validates the derivation path first and bounds the seed to the BIP32 master-seed range (16..=64 bytes, new `Error::InvalidSeedLength`) before doing any HMAC work (`bf9b646`).
- Round 2 reveals are rejected on the exact per-config length **before** the SHAKE256 commitment hash runs, so a peer who pre-committed to an oversized blob (up to the 10.5 MB global deserializer bound) cannot force megabytes of hashing in a session whose legitimate reveal is kilobytes; protocol intake drops hash-bound but mis-sized reveals in O(1) (`36e1079`).

## Protocol state-machine correctness

- Aborted resharing sessions no longer strand the old share: recovery restores it so the party can rejoin a retried session (`5e5c7ef`).
- `round3_respond` failures **after** the peers' reveals were folded into the commitment aggregate now reset the session instead of leaving a poisoned aggregate in the "cleanly retryable" `AfterRound2` state, where a retry would double-count every peer's commitment. Pre-commit-point failures still leave the session clean for corrected retries (`243bb0d`). The trigger for the reset — a Round 1 broadcast from a party outside the DKG participant set, previously only detected inside `recover_share` — is now rejected by `round2_reveal` before the commit point, so the failure is early and recoverable and the round-3 reset is defense in depth.
- `DerivedKeyId` is bound to the DKG output public key, preventing cross-key derivation-ID collisions (`5599c69`).

## API contract enforcement

- `poly::shiftl`'s unchecked left shift is no longer reachable through public API with out-of-contract coefficients: it is crate-private and the `k_shiftl` docs state the real `2^(31-D)` bound (`6fe967c`).
- `KeccakState` encodes the SHAKE rate as a const-generic parameter, making the absorb/squeeze phase-and-rate mismatches flagged by review unrepresentable, and squeeze chunking canonical (`225e629`).
- `uniform_eta`'s rejection-sampling retry loop is documented as not a timing channel: two fixed blocks yield 544 nibbles at 15/16 acceptance, so a third block is a < 2^-600 event, and rejection counts are independent of the accepted values under standard XOF assumptions (`ec388fe`).

## Compatibility notes

Behavioral tightenings downstream consumers may notice:

- `hdwallet`: seeds outside 16..=64 bytes are now rejected by `ExtendedPrivKey::derive` (new `Error::InvalidSeedLength` variant). The Quantus SDK's `derive_hd_path` passes 64-byte BIP39 seeds and is unaffected.
- `threshold`: resharing `Action::SendPrivate` now carries `Zeroizing<Vec<u8>>`; `DkgConfig` fields are private (use the accessors); `SubsetContribution` and secret-key/share imports reject blobs that previously deserialized; `ThresholdSigner::round2_reveal` rejects Round 1 broadcasts from parties outside the DKG set (previously deferred to Round 3); `ResharingProtocol::take_existing_share` is renamed `abort_and_take_existing_share` (the name now carries its abort side effect); `all_broadcasts_received` is no longer exported.
- `dilithium`: `packing::unpack_sk` returns a `bool` canonicality flag; `poly::shiftl` is crate-private; `Keypair::to_bytes` and `SecretKey::to_bytes` return `Zeroizing` buffers (deref or `as_slice()` for access).

## Test plan

- [x] Each finding reproduced red before the fix and green after (error-variant or allocator/stack-probe assertions pin the mechanism, not just the outcome)
- [x] `cargo test --workspace` green (dilithium, hdwallet, threshold; unit + integration + e2e suites)
- [x] New regression suites: `threshold/tests/heap_zeroization.rs` (scanning allocator, 6 scenarios), `dilithium/tests/import_stack_zeroization.rs` (painted-stack probe, release builds), `hdwallet/tests/wormhole_zeroization.rs`
- [x] Release-mode runs for the stack-zeroization suite
