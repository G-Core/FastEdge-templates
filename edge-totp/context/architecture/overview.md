# Overview — What This Is

## The product

`totp-app` is an **edge-deployed MFA enhancer**: a customer who already runs a
website with its own login puts this FastEdge app **in front of their login** to
add a **TOTP (RFC 6238) second factor** — without building TOTP themselves, and
without rewriting their backend. They get: a hosted 6-digit challenge page,
constant-time verification with clock-drift tolerance, replay and brute-force
protection, and a signed proof token their origin can verify.

## Governing principle — "issue centrally, verify everywhere"

The durable seed store is a **per-customer KV** (single-tenant, isolated); the edge
only ever *verifies* and issues a short-lived signed assertion — an `mfa_session`
cookie the filter checks, or an ES256 proof the origin verifies. The customer's site
stays the source of truth for *who the user is* (the password step); the edge is a
stateless verifier that produces a trustable "this user passed a second factor"
assertion.

## Edge-integration model

```
Browser ─▶ Customer site            ── password step
   │
   └─ (user enrolled in TOTP) ─▶ [ Gcore FastEdge: totp-app ]
                                      ├─ hosts the OTP challenge page
                                      ├─ verifies the code (HMAC, drift window)
                                      ├─ blocks replay / brute force (Cache)
                                      └─ issues a signed proof the origin verifies
```

The TOTP **seed** lives in the per-customer KV store. The customer site keeps owning
identity; the edge proves only that a second factor succeeded. How a customer wires
this into their login is in [../integration.md](../integration.md).
