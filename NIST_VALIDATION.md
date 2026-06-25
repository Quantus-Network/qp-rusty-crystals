# NIST validation & standards notes

Working notes on the US-government crypto validation/standardization paths
relevant to this repo, and what we've actually wired up so far.

There are two distinct things people conflate, plus the threshold track:

| Layer | Acronym | What it is | Self-service? |
|-------|---------|------------|---------------|
| Algorithm conformance | **CAVP** (Cryptographic Algorithm Validation Program), run via the **ACVTS** server using the **ACVP** protocol | NIST generates known-answer test vectors for your declared capabilities; you run them and return outputs; it checks them. Produces an **algorithm certificate**. | **Demo server: free / self-serve.** Production server (real certs) only via an accredited lab. |
| Module certification | **CMVP** (Cryptographic Module Validation Program), against **FIPS 140-3** (= ISO 19790) | Validates the whole crypto *module* (boundary, key mgmt, self-tests, roles, docs). Produces the **validation certificate** on NIST's public list. CAVP algo certs are a prerequisite. | No — requires an NVLAP-accredited **CST lab**; months + real money. |
| Threshold standardization | **MPTC** (Multi-Party Threshold Cryptography), **NIST IR 8214C** | NIST's "First Call for Multi-Party Threshold Schemes" (final Jan 20, 2026). Collects threshold versions of NIST primitives (incl. "ML-DSA sign", Class N). Not a cert — a public reference-materials process. | Public submission process. |

Key framing: **CAVP/ACVP is conformance testing, not formal verification and not
a security proof.** It checks "does our code produce NIST's expected outputs on
these vectors (including forced rejection paths)?" — weaker than full functional
correctness (all inputs; see the Lean/Aeneas discussion) and orthogonal to the
EUF-CMA security argument (that stays in `threshold/src/resharing/SECURITY_PROOF.md`
and the paper). But it is the axis that actually gates federal procurement
(FISMA / FedRAMP require a FIPS 140-3 *validated module*).

## What's done: free self-service ACVP KAT harness (ML-DSA-87)

Implemented in **`dilithium/src/acvp.rs`** (a `#[cfg(test)]` crate-internal
module) against vendored NIST vectors in **`dilithium/tests/acvp_vectors/`**.

Run it:

```bash
cargo test -p qp-rusty-crystals-dilithium --lib acvp -- --nocapture
```

Coverage (all passing, bit-for-bit against NIST's expected outputs):

| Mode | Vectors | What it exercises |
|------|---------|-------------------|
| keyGen | 25 | `seed (xi) -> (pk, sk)` byte-exact (`crate::sign::keypair`) |
| sigGen | 30 | `Sign_internal(sk, M, rnd)` byte-exact — both deterministic (`rnd = 0^32`) and hedged (vector-supplied `rnd`); covers the rejection-sampling loop |
| sigVer | 15 | `Verify_internal(pk, M, sig)` accept **and** reject cases (modified z / c / hint / etc.) |

Scope / TCB of this harness (deliberately bounded):
- **ML-DSA-87 only** (the only parameter set this crate implements).
- **Internal interface, `externalMu == false`** groups — i.e. FIPS 204
  `Sign_internal`/`Verify_internal`, which our `pub(crate)` functions implement
  directly. The public `ml_dsa_87` API additionally applies the FIPS 204
  external domain-separation prefix (`0 || len(ctx) || ctx || M`); the external
  interface and HashML-DSA (preHash) groups are **not** covered here.
- **Bounded to the vendored vector set** — it is KAT conformance, not a proof
  over all inputs.

### Updating / regenerating the vectors

Vectors are filtered from the NIST source with `jq` (requires network):

```bash
base=https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files
for m in keyGen sigGen sigVer; do
  curl -sSL "$base/ML-DSA-$m-FIPS204/internalProjection.json" -o /tmp/$m.json
done
# keyGen: all ML-DSA-87 groups
jq -c '{algorithm,mode,revision,testGroups:[.testGroups[]|select(.parameterSet=="ML-DSA-87")]}' \
  /tmp/keyGen.json > dilithium/tests/acvp_vectors/keygen_ml_dsa_87.json
# sig{Gen,Ver}: ML-DSA-87, internal interface, externalMu=false
for m in sigGen sigVer; do
  out=$(echo $m | tr 'A-Z' 'a-z')
  jq -c '{algorithm,mode,revision,testGroups:[.testGroups[]|select(.parameterSet=="ML-DSA-87" and .signatureInterface=="internal" and .externalMu==false)]}' \
    /tmp/$m.json > dilithium/tests/acvp_vectors/${out}_ml_dsa_87.json
done
```

### Next steps for ACVP coverage (cheap, optional)
- Add the **external-interface** sigGen/sigVer groups via the public
  `ml_dsa_87` API (exercises the domain-separation prefix + context handling).
- Wire the harness into CI (it's fast — ~1.3 s).

## Path to an actual FIPS 140-3 certificate (base ML-DSA-87)

Conformance KATs are necessary but not sufficient. For a real CMVP cert we'd need:
- An **NVLAP-accredited CST lab** + the production ACVTS server (algorithm certs).
- A defined **cryptographic module boundary** and FIPS 140-3 docs.
- Module **self-tests / CASTs** per IG 10.3.A, including a signing CAST that
  **covers all rejection-sampling loop paths**, a verify CAST, KeyGen CAST with
  fixed randomness, and a pairwise consistency test (sign-then-verify) after
  KeyGen.
- ML-DSA **SHALL NOT use floating-point math** (worth auditing our code/deps).

This is well-trodden (Apple corecrypto, libcrux, `mldsa-native` have done it) and
is an engineering/assurance exercise, not novel work.

## Path for the novel part: NIST MPTC threshold call (NIST IR 8214C)

This is the more relevant US-gov target for *our* contribution (threshold
resharing), since there is no FIPS standard for threshold ML-DSA to validate
against. The **Mithril team has already filed a preview** to this call
(`csrc.nist.gov/.../TCall-1/Mithril-PW01.pdf`), so it's a direct analog of
"imitate Mithril and publish."

A package submission requires:
- a **technical specification**,
- an **open-source reference implementation**,
- a **report on experimental evaluation**, and
- **patent-claim disclosures**.

We already have most of this raw material (`threshold/` crate, benchmarks,
`SECURITY_PROOF.md`, `threshold/papers/PAPER_PLAN.md`). Timeline: preview
opportunities at MPTS 2026; package-submission deadline around Nov 2026
(confirm on the CSRC threshold-cryptography page).

## Other regime (for completeness)
- **Common Criteria** (ISO 15408, EAL levels): international, evaluator-driven
  rather than automated. CMVP is the crypto-specific, automated-testing one.

## References
- CAVP: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
- ACVP ML-DSA test design: https://pages.nist.gov/ACVP/draft-celi-acvp-ml-dsa.html
- ACVP vectors: https://github.com/usnistgov/ACVP-Server
- NIST MPTC / IR 8214C: https://csrc.nist.gov/projects/threshold-cryptography
