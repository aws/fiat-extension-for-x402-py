# Agent Pay x402 Extension — SDK Guide

**Package:** `fiat-extension-for-x402`
**Module:** `fiat_extension_x402`
**Runtime:** Python ≥ 3.9

This guide explains how the SDK works conceptually. For task-oriented quickstarts, see the
[README](../README.md); for the request/response sequence, see
[payment-flow.md](./payment-flow.md).

## Table of Contents

1. [The three roles](#1-the-three-roles)
2. [The two-token model](#2-the-two-token-model)
3. [Quote tokens](#3-quote-tokens)
4. [Payment tokens](#4-payment-tokens)
5. [Sentinel values](#5-sentinel-values)
6. [Verification logic](#6-verification-logic)
7. [Settlement](#7-settlement)
8. [Authentication](#8-authentication)
9. [DPoP](#9-dpop)
10. [Discovery and caching](#10-discovery-and-caching)
11. [Error hierarchy](#11-error-hierarchy)
12. [Module map](#12-module-map)

---

## 1. The three roles

The x402 protocol defines three roles. Agent Pay implements all three for fiat payments:

| Role | Who plays it | What it does | SDK surface |
|------|--------------|--------------|-------------|
| **Resource server** | The seller's API | Protects endpoints, emits HTTP 402 with a signed quote, verifies payments, delivers the resource | `enhance_payment_requirements`, `AgentPayResourceServer`, the web middleware |
| **Client** | The buyer's AI agent | Reads a 402, obtains a payment token from Agent Pay, retries with proof of payment | `AgentPayClient`, `AgentPayClientBuilder` |
| **Facilitator** | The Agent Pay service | Authorizes, signs, verifies, and captures payments | `AgentPayFacilitatorClient` |

A notable property of Agent Pay: **the Agent Pay service is both the payment authorizer
and the facilitator**. There is no separate facilitator service to run — the buyer calls
Agent Pay to authorize, and the seller verifies the result against Agent Pay's public
keys. `AgentPayFacilitatorClient` is the seller-side adapter that performs that
verification and the (no-op) settlement.

## 2. The two-token model

The entire security model rests on two JWTs:

| Token | Signed by | Means |
|-------|-----------|-------|
| **Quote token** | The seller | "I will sell you this resource for $0.15 USD, and this offer expires in 5 minutes." |
| **Payment token** | Agent Pay | "I authorized $0.15 USD from buyer X. Here is the payment id." |

The quote token is embedded in the 402 response at `extra.quoteToken`. The buyer forwards
it to Agent Pay, which returns a payment token that **embeds the original quote token**.
The seller verifies both: that Agent Pay signed the payment, and that the quote inside it
is the exact quote the seller issued.

## 3. Quote tokens

A quote token is a JWT signed by the seller's key (ES256/ES384/ES512). The claims are
constructed by `enhance_payment_requirements`:

```json
{
  "iss": "https://api.example.com",
  "aud": "aws:marketplace",
  "iat": 1709654400,
  "exp": 1709654700,
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "price": { "amount": "0.15", "currency": "USD" },
  "payTo": "seller-agent-pay-id",
  "reference": "RESOURCE",
  "description": "Premium API access",
  "dimensions": { "tokens": 1500 },
  "settlement": { "method": "INST" },
  "support": { "uri": "https://support.example.com", "method": "human" },
  "terms": [{ "description": "API Terms of Service", "uri": "https://example.com/tos" }]
}
```

- `iss` is the seller's `service_url` — the verifier discovers the seller's public key at
  `{iss}/.well-known/jwks.json`.
- `aud` is always `aws:marketplace` (`AGENT_PAY_AUDIENCE`).
- Default validity is 300 seconds (`DEFAULT_QUOTE_VALIDITY_SECONDS`); override it via
  `maxTimeoutSeconds` in the input requirements.
- `price`, `payTo`, and `reference` are always present. `description`, `dimensions`,
  `settlement`, `support`, and `terms` are included only when supplied in `extra`.

You can decode and validate a quote token with `fiat_extension_x402.schemas.parse_quote_token`
(raises) or `safe_parse_quote_token` (returns a result object), and verify its signature
with `verify_quote_token`.

## 4. Payment tokens

A payment token is a JWT signed by Agent Pay (`iss` = `awsmp-agentpay.amazonaws.com`,
`PAYMENT_JWT_ISSUER`):

```json
{
  "iss": "awsmp-agentpay.amazonaws.com",
  "sub": "buyer-identity",
  "aud": "https://api.example.com",
  "iat": 1709654410,
  "exp": 1709658010,
  "payment_id": "awsmp-a1b2c3d4-...",
  "quote_token": "<original quote token JWT>",
  "cnf": { "jkt": "sha256-thumbprint-of-dpop-key" }
}
```

The SDK reads `quote_token` from the top level, falling back to a nested
`payment_context.quote_token` for compatibility. `cnf.jkt` is present only when DPoP is
used (see [§9](#9-dpop)). Default validity is 3600 seconds
(`DEFAULT_PAYMENT_VALIDITY_SECONDS`).

## 5. Sentinel values

The x402 `PaymentRequirements` shape requires `payTo` and `maxTimeoutSeconds`. In Agent
Pay both are redundant because the **signed** quote token is the authoritative source —
the outer fields are unsigned and could be tampered with. Rather than diverge from the
core shape, `enhance_payment_requirements` writes sentinel values:

| Field | Value after enhancement | Why |
|-------|-------------------------|-----|
| `payTo` | `urn:x402:agent-pay:see-quote` (`AGENT_PAY_SENTINEL_PAY_TO`) | Signals "the quote token's `payTo` is authoritative." |
| `maxTimeoutSeconds` | `exp - iat` of the quote | Numerically valid for any middleware that inspects it, but derived from the signed quote. |

The verifier and the buyer use the quote token directly and ignore these outer fields.

## 6. Verification logic

`AgentPayFacilitatorClient.verify(payment_token, expected_quote_token, requirements)`
performs these checks, returning a `VerifyResponse` (it does **not** raise on an invalid
payment):

1. **Payment token signature** — fetch Agent Pay's JWKS and verify the JWT signature.
   Agent Pay's keys are always fetched fresh (their endpoint sends `Cache-Control:
   no-store`).
2. **Expiry** — reject if the payment token's `exp` is in the past
   (`invalid_reason="expired"`).
3. **Quote extraction** — pull `quote_token` out of the verified payment claims.
4. **Quote match** — constant-time compare against `expected_quote_token` (the
   `extra.quoteToken` the seller issued). A mismatch is `invalid_reason="invalid_payment"`.
5. **Quote signature** — decode the quote token, discover the seller's JWKS from its `iss`
   (`{iss}/.well-known/jwks.json`), and verify the quote's signature.
6. **Amount & currency** — the quote's `price.amount` / `price.currency` must equal the
   `amount` and `asset` (minus the `iso4217:` prefix) in `requirements`.
7. **DPoP** — if the payment token carries `cnf.jkt`, a matching proof is **mandatory**
   (see [§9](#9-dpop)).

On success, `result.is_valid` is `True` and `result.payer` is the payment token's `sub`.
On failure, `result.invalid_reason` and `result.invalid_message` explain why.

Only algorithms on the allowlist (`fiat_extension_x402.security.ALLOWED_ALGORITHMS`) are
accepted for any signature check.

## 7. Settlement

`AgentPayFacilitatorClient.settle(payment_id=..., network=...)` returns a successful
`SettleResponse` immediately. Agent Pay **auto-captures funds when the payment is created**
(step 3 of the flow), so there is no separate capture call — settlement is a no-op kept
for x402 interface compatibility.

## 8. Authentication

Agent Pay API calls (buyer side) are authenticated. The SDK provides four authenticators,
all implementing a common `Authenticator` protocol that takes a `SignedRequest` and
returns a signed one:

| Type | Class | Notes |
|------|-------|-------|
| AWS SigV4 | `AwsSigV4Authenticator` | The production path — charges land on the buyer's AWS bill. Signs with `botocore`. |
| API key | `ApiKeyAuthenticator` | Configurable header name and optional prefix. |
| OAuth2 | `OAuth2Authenticator` | Bearer access token with an optional refresh hook. |
| Custom | `CustomAuthenticator` | Wraps any `SignedRequest -> SignedRequest` callable. |

`create_authenticator(config)` builds the right one from a dict with a `type` key
(`"awsSigV4"`, `"api-key"`, `"oauth2"`, `"custom"`). `AgentPayClient` also accepts AWS
`credentials=` directly and constructs a SigV4 authenticator for you;
`create_env_credential_provider()` reads `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` /
`AWS_SESSION_TOKEN` from the environment.

## 9. DPoP

DPoP (Demonstrating Proof-of-Possession, RFC 9449) binds a payment token to the buyer's
ephemeral key so a stolen token cannot be replayed.

1. The buyer generates a key pair — `generate_dpop_keypair("ES256")` (ES256/ES384/ES512;
   EC keys only for Agent Pay binding).
2. The buyer attaches the public key to the payment request — `to_dpop_jwk(keypair)`
   passed as `dpop_jwk` on `CreateAgentPaymentRequest`. Agent Pay records its thumbprint
   in the payment token's `cnf.jkt`.
3. On each retry the buyer creates a proof — `create_dpop_proof(keypair, {"htm": ...,
   "htu": ...})` — bound to the HTTP method and URL.
4. The verifier passes the proof via `verify_options`; `verify` confirms the proof's
   thumbprint matches `cnf.jkt` and validates the proof (`verify_dpop_proof`).

A DPoP-bound token presented **without** a proof is rejected with
`invalid_reason="dpop_required"`. Replay protection is available by supplying a
`nonce_store` (any object with `has`/`add`) in the proof verification options.

## 10. Discovery and caching

`fiat_extension_x402.discovery` maintains a network registry (`register_network`,
`get_registered_networks`, `unregister_network`) and supports OIDC-style endpoint
discovery (`discover_agent_pay_endpoints`, returning `AgentPayDiscoveryMetadata`).

Caches and their default lifetimes:

| Cache | TTL | Cleared by |
|-------|-----|------------|
| Seller JWKS (in the facilitator) | 1 hour | new client instance |
| Service JWKS (utils) | 1 hour | `clear_service_jwks_cache()` |
| Agent Pay endpoint JWKS (discovery) | 1 hour | `clear_jwks_cache()` |
| OIDC discovery metadata | 24 hours | `clear_discovery_cache()` |

Agent Pay's own signing keys are intentionally **not** cached — its JWKS endpoint enforces
`Cache-Control: no-store`, so every verification fetches them fresh.

## 11. Error hierarchy

All SDK errors derive from `AgentPayError` (which carries a `code` and optional `details`):

| Error | Code | When raised |
|-------|------|-------------|
| `ValidationError` | `VALIDATION_ERROR` | Schema/format failures, missing fields, failed API calls |
| `SignatureError` | `SIGNATURE_ERROR` | JWT signature verification failed |
| `ExpiryError` | `EXPIRY_ERROR` | A token's `exp` is in the past |
| `MismatchError` | `MISMATCH_ERROR` | Expected vs. actual mismatch during verification |
| `DPoPError` | `DPOP_ERROR` | DPoP proof verification failed |
| `IdempotencyConflictError` | `IDEMPOTENCY_CONFLICT` | A `clientToken` was reused with different parameters |
| `SigningError` | `SIGNING_ERROR` | KMS quote-token signing failed (from `fiat_extension_x402.signers`) |

`AgentPayFacilitatorClient.verify` is the exception to the "errors raise" rule: it
captures failures and returns a `VerifyResponse` with `is_valid=False`.

## 12. Module map

```
fiat_extension_x402/
├── __init__.py          # Public API — everything below is re-exported here
├── constants.py         # Scheme identifiers, audiences, defaults, sentinels
├── client.py            # AgentPayClient — Agent Pay HTTP API (Create/Get/List)
├── server/scheme.py     # enhance_payment_requirements — quote token generation
├── discovery.py         # Network registry + OIDC endpoint discovery + caches
├── security.py          # Algorithm allowlist, constant-time compare, URL validation
├── utils.py             # JWT decode/verify helpers, transaction ids, money parsing
├── exceptions.py        # AgentPayError and the error hierarchy
├── schemas/             # Pydantic models + parse helpers (quote/payment/API bodies)
├── builders/            # create/build_agent_pay_resource_server + _client (two-phase)
├── facilitator/         # AgentPayFacilitatorClient, InProcessFacilitatorClient, types
├── auth/                # Authenticators (SigV4, API key, OAuth2, custom) + factory
├── signers/             # KMS signer + local signer adapters + ServiceAgentPaySigner
├── dpop/                # Key generation, proof creation, proof verification
└── middleware/          # FastAPI + Flask middleware and shared route types
```

For runnable code, see [`examples/`](../examples).
