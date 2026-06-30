# totp-app — Context Index

> **How to use this folder:** Read *this index*, then open **only** the file(s)
> relevant to your task. Each file is one focused concept. You do **not** need to
> read the whole tree to help. Treat the code as the source of truth — if a doc and
> the code disagree, the code wins (and fix the doc).

## What this app is (one paragraph)

`totp-app` is a **FastEdge edge MFA bolt-on that adds TOTP (RFC 6238) two-factor
auth in front of a customer's existing login.** The customer keeps their own
password login; the edge hosts the 6-digit challenge, verifies the code, guards
against replay/brute-force, and produces a signed assertion the origin trusts. It
ships as two deployables: **`otp-app`** (TypeScript HTTP app — challenge, verify,
enroll, activate, logout, JWKS) and **`otp-filter`** (Rust proxy-wasm enforcement
filter that gates protected paths on the `mfa_session` cookie). Two enforcement
profiles: **A** (default — the filter enforces, zero origin code) and **B** (opt-in
— the origin verifies an ES256 proof via JWKS and mints its own session).

## Map

### architecture/ — how it fits together
- [overview.md](architecture/overview.md) — what the product is and the "issue
  centrally, verify everywhere" model. **Start here.**
- [flow.md](architecture/flow.md) — the end-to-end enroll / challenge / verify flow,
  the handoff ticket, the KV seed read, the two enforcement profiles, and the **PoP
  reasoning** behind fetching the seed at verify time.
- [storage-and-secrets.md](architecture/storage-and-secrets.md) — where the seed
  lives (**KV-only**, per-customer isolated store), the full config/env/secrets list,
  and the Gcore KV write API.

### design/ — how it's built
- [decisions.md](design/decisions.md) — the design: components, KV-only storage,
  trust handoff, TOTP, the two profiles, token algorithms/TTLs, QR.
- [runtime-constraints.md](design/runtime-constraints.md) — the FastEdge JS runtime
  facts that constrain the implementation (crypto.subtle matrix, read-only KV,
  POP-local Cache, no encrypt/decrypt).

### security/ — threat model
- [threat-model.md](security/threat-model.md) — trust model, the protections in the
  code today, and the **residual risks knowingly accepted** (cross-PoP single-use /
  brute force, KV revocation lag, plaintext seeds at rest). Read before touching the
  verify or enforcement path, and before deploying.

### integration.md — customer wiring
- [integration.md](integration.md) — how a customer wires TOTP into their existing
  login: the three changes they make, the shared keys, and what the origin still
  owns.

## Quick task → file routing
- *"What is this?"* → architecture/overview.md
- *"How does the whole flow work / why fetch the seed at verify time?"* → architecture/flow.md
- *"Where do seeds live? what config exists?"* → architecture/storage-and-secrets.md
- *"How is it built?"* → design/decisions.md
- *"Can the runtime even do TOTP?"* → design/runtime-constraints.md
- *"What does it defend against / what risks are accepted?"* → security/threat-model.md
- *"How does a customer integrate it?"* → integration.md
- *"How do I build / deploy it?"* → README.md
