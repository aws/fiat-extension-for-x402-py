# Agent Pay x402 Extension — SDK Guide

**Package:** `fiat-extension-for-x402`
**Module:** `fiat_extension_x402`
**Runtime:** Python ≥ 3.10

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
12. [The x402 schemes](#12-the-x402-schemes)
13. [Module map](#13-module-map)

---

## 1. The three roles

The x402 protocol defines three roles. Agent Pay implements all three for fiat payments:

| Role | Who plays it | What it does | SDK surface |
|------|--------------|--------------|-------------|
| **Resource server** | The seller's API | Protects endpoints, emits HTTP 402 with a signed quote, verifies payments, delivers the resource | `AgentPayServerScheme` (registered on an `x402ResourceServerSync`), `enhance_payment_requirements`, `AgentPayResourceServer`, the web middleware |
| **Client** | The buyer's AI agent | Reads a 402, obtains a payment token from Agent Pay, retries with proof of payment | `AgentPayClientScheme` (registered on an `x402ClientSync`), `AgentPayClientBuilder`, `AgentPayClient` |
| **Facilitator** | The Agent Pay service | Authorizes, signs, verifies, and captures payments | `AgentPayFacilitatorScheme` (registered on an `x402FacilitatorSync`), `AgentPayFacilitatorClient` |

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
2. **Payment expiry** — reject if the payment token's `exp` is in the past.
3. **Quote extraction** — pull `quote_token` out of the verified payment claims.
4. **Quote match** — constant-time compare against `expected_quote_token` (the
   `extra.quoteToken` the seller issued).
5. **Quote signature** — decode the quote token, locate the seller's public key (by
   default from its `iss`, at `{iss}/.well-known/jwks.json`; see [key
   resolution](#seller-key-resolution) below), and verify the quote's signature.
6. **Quote expiry** — reject if the quote token's own `exp` is in the past.
7. **Amount & currency** — the quote's `price.amount` / `price.currency` must equal the
   `amount` and `asset` (minus the `iso4217:` prefix) in `requirements`.
8. **DPoP** — if the payment token carries `cnf.jkt`, a matching proof is **mandatory**
   (see [§9](#9-dpop)).

On success, `result.is_valid` is `True` and `result.payer` is the payment token's `sub`.
On failure, `result.invalid_reason` and `result.invalid_message` explain why:

| `invalid_reason` | Raised when |
|---|---|
| `payment_expired` | The payment token's `exp` has passed |
| `invalid_quote` | The embedded quote is missing, does not match the expected quote, or carries no `iss` |
| `quote_expired` | The quote token's `exp` has passed |
| `invalid_payment` | The quote's price does not match the requirements' amount/asset |
| `dpop_required` | The payment token is DPoP-bound but no proof was supplied |
| `dpop_invalid` | The proof's thumbprint does not match the token's `cnf.jkt` |
| `verification_failed` | Any other failure (signature, JWKS fetch, malformed token) |

Only algorithms on the allowlist (`fiat_extension_x402.security.ALLOWED_ALGORITHMS`) are
accepted for any signature check.

### Seller key resolution

Step 5 needs the seller's public key. Three strategies, in precedence order:

| Strategy | How to select it | Where the key comes from |
|---|---|---|
| `KmsSellerKeyResolver(kms_key_arn=..., region=...)` | `seller_key_resolver=` | KMS `GetPublicKey`, cached per client |
| `JwksSellerKeyResolver(jwks_url=...)` | `seller_key_resolver=` | `{jwks_url}/.well-known/jwks.json` |
| Issuer discovery (default) | pass nothing | `{quote.iss}/.well-known/jwks.json` |

An explicit resolver supersedes `iss` completely — the issuer is never fetched, so a quote
with no `iss` still verifies. With no resolver configured, `iss` is the only locator, so a
quote missing it fails with `invalid_quote`. Both resolvers are accepted by the
resource-server builders as well, and are re-exported from the package root.

### Advertising supported kinds

`get_supported()` fetches Agent Pay's `/.well-known/x402-supported` document (from the
client's configured `agent_pay_base_url`) and raises `ValidationError` on a non-2xx.
Constructing the client with `network_filter={"aws:base", ...}` drops kinds for any network
outside that set, so a facilitator advertises only what the integrator registered.

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
   passed as `dpop_jwk` on `AgentPayClientOptions` (framework path, applied to every
   payment) or on `CreateAgentPaymentRequest` (direct path, per call). Agent Pay records
   its thumbprint in the payment token's `cnf.jkt`.
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

> Two distinct things are called "registering a network". `discovery.register_network(
> network, base_url)` maps a network to an Agent Pay endpoint URL.
> `AgentPayClientBuilder.register_network(network)` (see §13) registers the *scheme* with
> x402 core so it can serve that network. They are unrelated.

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

## 12. The x402 schemes

Agent Pay is an x402 *scheme*, not a bespoke client. `AgentPayClientScheme` implements
x402 core's `SchemeNetworkClient` contract, so it registers onto an `x402ClientSync`
alongside any other mechanism and is selected by network + scheme name:

```python
from x402 import x402ClientSync
from fiat_extension_x402 import AgentPayClientScheme, AgentPayConfig

client = x402ClientSync()
client.register("aws:base", AgentPayClientScheme(
    agent_pay_id="YOUR_AWS_ACCOUNT_ID",
    agent_pay=AgentPayConfig(credentials=my_credentials),
))
payload = client.create_payment_payload(payment_required)
```

`create_agent_pay_client(...)` (§the builder) is sugar over exactly this: it builds the
transport, the scheme, and the x402 client, and `register_network` forwards to
`x402ClientSync.register`. Wildcard families work because core resolves them —
`register_network("aws:*")` serves every `aws:` network, with exact matches taking
precedence.

**What the scheme returns.** The scheme produces only the *inner* payload dict:

```python
{"paymentToken": "eyJ...", "paymentId": "awsmp-...", "transactionId": "awsmp-..."}
```

x402 core wraps it into the full `PaymentPayload`, adding `x402Version`, `accepted` (the
selected requirements), `resource`, and `extensions`. `transactionId` is a deprecated
alias always equal to `paymentId`, kept for pre-v2 verifiers.

**Only the quote token is sent.** The signed quote is the authoritative source for amount,
currency, and recipient, so the scheme forwards just `quoteToken` (plus its generated
`clientToken`, and `dpopJwk` when configured). The outer `amount`/`asset`/`payTo` fields —
where `payTo` is the sentinel `urn:x402:agent-pay:see-quote` — are deliberately not
transmitted; a tampered outer field cannot affect what is charged.

**Scheme contract.** `x402` calls `create_payment_payload(requirements)` synchronously
with a single argument, and expects only the inner payload dict back — core supplies
`x402Version`, `accepted`, `resource`, and `extensions` itself. A scheme must therefore
not set those fields.

### The seller and verifier schemes

The other two x402 roles have schemes as well, so a whole seller can be built on the
framework instead of calling the SDK's functions directly:

```python
from x402 import x402FacilitatorSync, x402ResourceServerSync
from x402.schemas import ResourceConfig
from fiat_extension_x402 import AgentPayFacilitatorScheme, AgentPayServerScheme

# The verifier. Its supported-kinds response is what lets the resource server
# below resolve the agent-pay scheme, so build it first.
facilitator = x402FacilitatorSync()
facilitator.register(["aws:base"], AgentPayFacilitatorScheme())

server = x402ResourceServerSync(facilitator)
server.register("aws:base", AgentPayServerScheme(signer=signer))
server.initialize()

requirements = server.build_payment_requirements(
    ResourceConfig(scheme="agent-pay", network="aws:base",
                   pay_to="your-seller-id", price="$0.50")
)
payment_required = server.create_payment_required_response(requirements)   # the 402 body

# Later, when the buyer retries with a payment:
result = facilitator.verify(payment_payload, payment_payload.accepted)
facilitator.settle(payment_payload, payment_payload.accepted)  # no-op; auto-captured
```

`AgentPayServerScheme.parse_price` accepts `"$0.50"`, `"0.50 EUR"`, `0.50`, or an
`AssetAmount`, and normalises to a decimal amount plus an `iso4217:` asset — Agent Pay
prices are fiat, so there is no atomic-unit conversion. `enhance_payment_requirements`
delegates to the standalone function, so both paths mint identical quote tokens.

Two wiring details worth knowing:

- **The resource server needs a facilitator.** `build_payment_requirements` resolves a
  scheme through the supported-kinds the facilitator advertises, so
  `x402ResourceServerSync(None)` raises `SchemeNotFoundError`. Pass the facilitator (or
  an HTTP facilitator client) and call `initialize()`.
- **The signer is async, the scheme is sync.** x402 core never awaits
  `enhance_payment_requirements`, even on the async server, so the scheme drives the
  async signer to completion internally. This is transparent, and works both inside and
  outside a running event loop.

`AgentPayFacilitatorScheme.verify` reads the payment token from the payload and the
expected quote token from `requirements.extra`, so nothing has to be threaded by hand.
Per-request DPoP details go under the `agent-pay` key of the payload's `extensions`:

```python
PaymentPayload(..., extensions={"agent-pay": {
    "dpop_proof": proof, "method": "GET", "url": request_url}})
```

Per the x402 contract, an invalid payment comes back as a `VerifyResponse` with
`is_valid=False` and an `invalid_reason` — it does not raise.

### AWS-preconfigured variants

`fiat_extension_x402.networks` holds thin subclasses that pin the AWS Marketplace Agent Pay
endpoint, so callers on AWS don't have to supply it. Behaviour is otherwise identical to the
base schemes:

```python
from fiat_extension_x402.networks import (
    AgentPayAWSClientScheme,
    AgentPayAWSFacilitatorScheme,
    AgentPayAWSServerScheme,
)

client.register("aws:base", AgentPayAWSClientScheme(agent_pay_id="YOUR_AWS_ACCOUNT_ID"))
```

`AgentPayAWSFacilitatorScheme` additionally defaults its `agent_pay_id` to
`'aws-agent-pay'`, which is what it advertises through `get_extra` / `get_signers`. All
three are re-exported from the package root.

## 13. Module map

```
fiat_extension_x402/
├── __init__.py          # Public API — everything below is re-exported here
├── constants.py         # Scheme identifiers, audiences, defaults, sentinels
├── client.py            # AgentPayClient — Agent Pay HTTP API (Create/Get/List)
├── client_scheme.py     # AgentPayClientScheme — the x402 buyer scheme (agent-pay)
├── server_scheme.py     # AgentPayServerScheme — the x402 seller scheme
├── facilitator_scheme.py # AgentPayFacilitatorScheme — the x402 verifier scheme
├── server/scheme.py     # enhance_payment_requirements — quote token generation
├── discovery.py         # Network registry + OIDC endpoint discovery + caches
├── security.py          # Algorithm allowlist, constant-time compare, URL validation
├── utils.py             # JWT decode/verify helpers, transaction ids, money parsing
├── exceptions.py        # AgentPayError and the error hierarchy
├── schemas/             # Pydantic models + parse helpers (quote/payment/API bodies)
├── builders/            # create/build_agent_pay_resource_server + _client (two-phase);
│                        #   the client builder registers the scheme on x402ClientSync
├── facilitator/         # AgentPayFacilitatorClient, InProcessFacilitatorClient, types;
│                        #   Kms/Jwks SellerKeyResolver for quote-key resolution
├── networks/            # AWS-preconfigured scheme variants (endpoint pinned)
├── _sync.py             # Drives async signers to completion from sync scheme methods
├── auth/                # Authenticators (SigV4, API key, OAuth2, custom) + factory
├── signers/             # KMS signer + local signer adapters + ServiceAgentPaySigner
├── dpop/                # Key generation, proof creation, proof verification
└── middleware/          # FastAPI + Flask middleware and shared route types
```

For runnable code, see [`examples/`](../examples).
