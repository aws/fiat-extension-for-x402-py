# Fiat Extension for x402 (Python)

Python SDK for AWS Marketplace Agent Pay — enables AI agents to pay for API calls using
the x402 protocol.

## What is Agent Pay?

Agent Pay enables HTTP APIs to accept pay-per-request payments via AWS Marketplace. When
a buyer's AI agent hits a seller's paid endpoint, the seller returns HTTP 402 with a
signed price quote. The agent pays via Agent Pay and retries with a payment token. The
seller verifies the token and delivers the resource. Charges appear on the buyer's AWS
bill.

The flow rests on two signed JWTs: a **quote token** (signed by the seller — "I will sell
this for $0.15") and a **payment token** (signed by Agent Pay — "I authorized $0.15 from
buyer X"). See [docs/sdk-guide.md](./docs/sdk-guide.md) for the full model.

## Installation

```bash
pip install fiat-extension-for-x402
```

The base install protects buyers and verifies payments. For the web middleware, install
the framework extra you need:

```bash
pip install "fiat-extension-for-x402[fastapi]"   # FastAPI middleware
pip install "fiat-extension-for-x402[flask]"      # Flask middleware
```

Requires Python 3.10+.

---

## Seller: Generate a quote token (402 response)

When a buyer requests a paid resource without payment, return a signed quote. Pick a
signer, build the payment requirements, and put them in a 402 response body.

### Option A: KMS-hosted key (recommended for AWS sellers)

The private key never leaves KMS — signing happens through the KMS `Sign` API. Use an
asymmetric EC key (`ECC_NIST_P384`, which maps to ES384).

```python
from fiat_extension_x402 import (
    KmsSignerConfig,
    create_kms_signer,
    enhance_payment_requirements,
)

# Once at startup.
signer = create_kms_signer(
    KmsSignerConfig(
        key_arn="arn:aws:kms:us-east-1:123456789012:key/your-key-id",
        region="us-east-1",
        service_url="https://api.your-service.com",  # becomes the quote token's `iss`
    )
)

# In your request handler, when payment is missing:
requirements = await enhance_payment_requirements(
    {
        "scheme": "agent-pay",
        "network": "aws:base",
        "payTo": "your-seller-id",
        "amount": "0.50",
        "asset": "iso4217:USD",
        "maxTimeoutSeconds": 300,
        "extra": {"description": "Premium API access"},
    },
    signer,
)

# Return HTTP 402 with this body:
# {"x402Version": 1, "accepts": [requirements]}
```

`enhance_payment_requirements` signs the quote token and embeds it at
`requirements["extra"]["quoteToken"]`. It also replaces `payTo` with a sentinel and
derives `maxTimeoutSeconds` from the quote — the signed quote is the authoritative source
for those fields (see [docs/sdk-guide.md](./docs/sdk-guide.md#sentinel-values)).

> **`service_url` must be non-empty.** It becomes the quote token's `iss` (issuer)
> claim, which Agent Pay requires — a token with an empty `iss` is rejected with
> `400 ... Missing or empty: [iss]`. Both signer constructors (`create_kms_signer`,
> `to_service_agent_pay_signer`) reject an empty or whitespace-only `service_url` at
> construction time, and `enhance_payment_requirements` refuses to sign one, so the
> misconfiguration surfaces immediately rather than at the service.

### Option B: Self-hosted key

Hold the signing key in process (for development, or when you manage your own key
material). Host the matching public key as a JWKS document at
`{service_url}/.well-known/jwks.json` so Agent Pay and the verifier can fetch it.

```python
from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1, generate_private_key
from fiat_extension_x402 import enhance_payment_requirements, to_service_agent_pay_signer

private_key = generate_private_key(SECP384R1())
public_jwk = {  # publish this (with "kid") at {service_url}/.well-known/jwks.json
    "kty": "EC", "crv": "P-384", "alg": "ES384", "use": "sig", "kid": "my-key-1",
    "x": "...", "y": "...",  # base64url EC coordinates
}

signer = to_service_agent_pay_signer(private_key, public_jwk, "https://api.your-service.com")

# Same enhance_payment_requirements(...) call as Option A.
```

> A runnable build-a-key-pair example lives in
> [`examples/end_to_end_demo.py`](./examples/end_to_end_demo.py).

---

## Buyer (AI agent): Authorize a payment

When your agent receives a 402 response, pull the quote token out of the body and exchange
it for a payment token via Agent Pay. The buyer authenticates with AWS SigV4 — charges
land on this AWS account's bill.

```python
from fiat_extension_x402 import AgentPayClient, create_env_credential_provider
from fiat_extension_x402.schemas import CreateAgentPaymentRequest

client = AgentPayClient(
    base_url="https://prod.agentpay.marketplace.aws.dev",
    credentials=create_env_credential_provider(),  # reads AWS_* from the environment
)

# `response_402` is the parsed 402 JSON body the seller returned.
quote_token = response_402["accepts"][0]["extra"]["quoteToken"]

# Calls POST /CreateAgentPayment; Agent Pay verifies the quote, captures, and signs a token.
payment = client.create_payment(CreateAgentPaymentRequest(quote_token=quote_token))
# payment.payment_id   -> "awsmp-..."
# payment.payment_token -> "eyJ..."  (signed by Agent Pay)
```

Retry the original request with the payment token in an `X-Payment` header — a
base64-encoded JSON payload the seller's verifier (or middleware) decodes:

```python
import base64
import json
import httpx

x_payment = {
    "x402Version": 1,
    "accepted": response_402["accepts"][0],
    "payload": {"paymentToken": payment.payment_token, "paymentId": payment.payment_id},
}
header = base64.b64encode(json.dumps(x_payment).encode()).decode()

result = httpx.get(url, headers={"X-Payment": header})
```

Pass `client_token=` to `CreateAgentPaymentRequest` for idempotency: reusing the same
token returns the same payment, and reusing it with different parameters raises
`IdempotencyConflictError`.

---

## Seller: Verify a payment token

When the buyer retries with a payment token, verify it before delivering the resource.
`AgentPayFacilitatorClient` fetches Agent Pay's JWKS to check the payment token signature,
confirms the embedded quote token matches the one you issued, validates the amount and
expiry, and (when present) checks the DPoP binding.

```python
from fiat_extension_x402 import AgentPayFacilitatorClient

facilitator = AgentPayFacilitatorClient()

result = facilitator.verify(
    payment_token,           # from the buyer's X-Payment payload
    expected_quote_token,    # the quoteToken you put in the 402 (extra.quoteToken)
    {                        # the requirements being satisfied
        "amount": "0.50",
        "asset": "iso4217:USD",
        "network": "aws:base",
    },
)

if result.is_valid:
    ...  # deliver the resource; result.payer is the buyer identity
else:
    ...  # 402 again; result.invalid_reason / result.invalid_message explain why

# Settle is a no-op — Agent Pay auto-captures at payment creation.
facilitator.settle(payment_id=payment_id, network="aws:base")
```

The seller's public key (used to verify the quote token's signature) is discovered from
the quote token's `iss` claim at `{iss}/.well-known/jwks.json`.

---

## Web middleware (all-in-one)

For sellers who want automatic 402 generation, verification, and settlement on protected
routes. The middleware wires up the signer, networks, and per-route pricing; after a
verified payment the details are attached to the request.

### FastAPI

```python
from fastapi import FastAPI, Request
from fiat_extension_x402 import KmsSignerConfig, create_kms_signer
from fiat_extension_x402.middleware.fastapi import (
    AgentPayFastAPIMiddlewareConfig,
    AgentPayRouteConfig,
    agent_pay_fastapi_middleware,
)

app = FastAPI()
signer = create_kms_signer(
    KmsSignerConfig(key_arn="...", region="us-east-1", service_url="https://api.example.com")
)

agent_pay_fastapi_middleware(
    AgentPayFastAPIMiddlewareConfig(
        agent_pay_base_url="https://prod.agentpay.marketplace.aws.dev",
        agent_pay_id="my-agent-pay-id",
        signer=signer,
        service_url="https://api.example.com",
        networks=["aws:base"],
        routes={
            "GET /api/premium": AgentPayRouteConfig(
                price="0.50", network="aws:base", pay_to="your-seller-id",
                description="Premium content",
            ),
        },
    )
)(app)


@app.get("/api/premium")
async def premium(request: Request) -> dict[str, object]:
    payment = request.state.agent_pay_payment  # set after verification
    return {"data": "premium content", "payer": payment.payer}
```

The Flask middleware is identical in shape — `agent_pay_middleware(AgentPayMiddlewareConfig(...))(app)`
from `fiat_extension_x402.middleware.flask`, with payment details on `g.agent_pay_payment`.
Both are demonstrated in [`examples/`](./examples).

---

## Payment flow

```
Buyer Agent                    Seller API                  Agent Pay Service
     |                              |                              |
     |--- GET /resource ----------->|                              |
     |<-- 402 + signed quote -------|                              |
     |                              |                              |
     |--- CreateAgentPayment (SigV4) --------------------------->|
     |<-- { paymentId, paymentToken } ---------------------------|
     |                              |                              |
     |--- GET /resource + token --->|                              |
     |                              |-- verify (JWKS + amount) -->|
     |<-- 200 OK + resource --------|                              |
```

See [docs/payment-flow.md](./docs/payment-flow.md) for the detailed sequence.

## Key constants

| Constant | Value | Description |
|----------|-------|-------------|
| `AGENT_PAY_SCHEME` | `agent-pay` | x402 scheme identifier for Agent Pay |
| `AGENT_PAY_AUDIENCE` | `aws:marketplace` | Required `aud` in quote tokens |
| `PAYMENT_JWT_ISSUER` | `awsmp-agentpay.amazonaws.com` | `iss` in payment tokens |
| `DEFAULT_NETWORK` | `aws:base` | Network identifier for AWS Marketplace |

Import these from `fiat_extension_x402.constants`.

## Supported algorithms

| Curve | KMS key spec | KMS signing algorithm | JWT `alg` |
|-------|--------------|-----------------------|-----------|
| P-256 | `ECC_NIST_P256` | `ECDSA_SHA_256` | ES256 |
| P-384 | `ECC_NIST_P384` | `ECDSA_SHA_384` | ES384 (default) |
| P-521 | `ECC_NIST_P521` | `ECDSA_SHA_512` | ES512 |

`KmsSignerConfig.algorithm` takes the KMS signing algorithm (default `ECDSA_SHA_384`).

## DPoP (optional token security)

Bind a payment token to the buyer's ephemeral key (RFC 9449) so a stolen token cannot be
replayed. The buyer generates a key pair, attaches its public JWK to the payment request,
and presents a proof on each retry; the verifier checks the proof against the token's
`cnf.jkt` binding.

```python
from fiat_extension_x402 import generate_dpop_keypair, to_dpop_jwk
from fiat_extension_x402.schemas import CreateAgentPaymentRequest

keypair = generate_dpop_keypair("ES256")  # ES256 / ES384 / ES512 (EC keys only)

payment = client.create_payment(
    CreateAgentPaymentRequest(quote_token=quote_token, dpop_jwk=to_dpop_jwk(keypair))
)
```

When verifying a DPoP-bound token, pass the proof via `verify_options`:

```python
from fiat_extension_x402 import create_dpop_proof

proof = create_dpop_proof(keypair, {"htm": "GET", "htu": "https://api.example.com/resource"})
result = facilitator.verify(
    payment_token, expected_quote_token, requirements,
    verify_options={"dpop_proof": proof, "method": "GET", "url": "https://api.example.com/resource"},
)
```

## Error handling

All SDK errors derive from `AgentPayError`:

```python
from fiat_extension_x402 import (
    AgentPayError,
    DPoPError,
    ExpiryError,
    IdempotencyConflictError,
    MismatchError,
    SignatureError,
    ValidationError,
)
```

| Error | When it's raised |
|-------|------------------|
| `ValidationError` | Schema/format failures, missing fields, failed API calls |
| `SignatureError` | JWT signature verification failed |
| `ExpiryError` | A token's `exp` is in the past |
| `MismatchError` | Expected vs. actual mismatch during verification |
| `DPoPError` | DPoP proof verification failed |
| `IdempotencyConflictError` | A `clientToken` was reused with different parameters |

Note that `AgentPayFacilitatorClient.verify` does not raise on a bad payment — it returns
a `VerifyResponse` with `is_valid=False` and an `invalid_reason`.

## Examples

See [`examples/`](./examples) for runnable code:

- [`end_to_end_demo.py`](./examples/end_to_end_demo.py) — the full flow in-process, no AWS
  account or network required (`python examples/end_to_end_demo.py`).
- [`fastapi_app.py`](./examples/fastapi_app.py) / [`flask_app.py`](./examples/flask_app.py)
  — protecting routes with the middleware.

## Development

This is a standard [hatchling](https://hatch.pypa.io/) project — it builds with the
PEP 517 toolchain (`python -m build`). Set up a virtualenv and install the package with
its dev extras:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Run the checks:

```bash
pytest              # unit + integration tests (e2e deselected by default)
ruff check .        # lint
ruff format --check .  # formatting
mypy src tests      # static types (strict)
```

## Testing

The test suite has three tiers under `tests/`:

| Tier | Path | Network / credentials | Default `pytest`? |
|------|------|-----------------------|-------------------|
| Unit | `tests/unit/` | None (fully mocked) | Yes |
| Integration | `tests/integration/` | None — in-process flow with mocked JWKS | Yes |
| End-to-end | `tests/e2e/` | Live Agent Pay service + AWS credentials | No (marked `e2e`, deselected) |

### Unit and integration tests

These are hermetic — no network, no credentials — and run by default:

```bash
pytest                          # unit + integration
pytest tests/unit               # unit only
pytest tests/integration        # in-process integration only
pytest --cov=fiat_extension_x402 --cov-report=term-missing   # with coverage
```

The integration tier wires the SDK's real components (server scheme → payment
token → facilitator verify/settle) into the full payment flow, serving all JWKS
endpoints from in-memory mocks (`respx`). No setup is required.

### End-to-end tests (live service)

The `tests/e2e/` suite drives the full buyer → service → seller flow against a
real Agent Pay endpoint. It is marked `e2e` and **deselected by default**
(`addopts = "-m 'not e2e'"`), so a bare `pytest` never runs it. Run it
explicitly:

```bash
pytest -m e2e tests/e2e
```

When the required configuration is not present, the e2e tests **skip** (they do
not fail), so this is safe to run anywhere.

> **Use the prod endpoint** (`https://prod.agentpay.marketplace.aws.dev`). Other
> stages lack a registered test seller, so the live-acceptance tests skip there.

#### Prerequisites

1. **Buyer AWS credentials** — resolved from the ambient AWS profile/environment
   (standard `AWS_*` variables or an active profile). The buyer identity must be
   allowed to call the Agent Pay APIs (`CreateAgentPayment`, `GetAgentPayment`,
   `ListAgentPayments`) and be allowlisted by the service.

2. **A registered seller** — a quote token signing key (KMS or self-hosted JWKS)
   whose public key is registered on a seller listing, and the listing's product
   id. The seller's `iss` must match its registered endpoint URL.

3. **Environment variables** (the e2e fixtures read these; any unset → skip):

   | Variable | Meaning |
   |----------|---------|
   | `AGENTPAY_URL` | Agent Pay service base URL |
   | `AGENTPAY_SELLER_KMS_KEY_ARN` | Seller quote-signing KMS key ARN (ECC_NIST_P384 / ES384) |
   | `AGENTPAY_SELLER_REGION` | Region of the seller KMS key (default `us-east-1`) |
   | `AGENTPAY_SELLER_SERVICE_URL` | Seller service URL — returns the 402 quote and serves the seller JWKS |
   | `AGENTPAY_SELLER_PROFILE` | *Optional* AWS profile for the seller account that owns the KMS key |

   The buyer (SigV4) and seller (KMS signing) are typically **different AWS
   accounts**. Buyer credentials come from the ambient profile (`AWS_PROFILE` /
   `AWS_*`); the seller KMS client is built from `AGENTPAY_SELLER_PROFILE` when
   set, so the two never have to share one profile. The happy-path tests source
   their quote from the seller's live HTTP 402 response (the authoritative,
   service-registered quote); the KMS signer is used only by the negative-path
   tests. When the target stage does not recognise the configured test seller,
   the service-acceptance tests **skip** (they do not fail).

   Example (values are placeholders — supply your own):

   ```bash
   export AGENTPAY_URL="https://prod.agentpay.marketplace.aws.dev"  # prod only for now
   export AGENTPAY_SELLER_KMS_KEY_ARN="arn:aws:kms:us-east-1:<account>:key/<key-id>"
   export AGENTPAY_SELLER_REGION="us-east-1"
   export AGENTPAY_SELLER_SERVICE_URL="https://<seller-endpoint>"
   export AGENTPAY_SELLER_PROFILE="<seller-profile>"   # seller KMS account
   # Buyer credentials come from the active AWS profile, e.g.:
   export AWS_PROFILE="<buyer-profile>"

   pytest -m e2e tests/e2e
   ```

   Do not commit real account ids, key ARNs, or endpoints — keep them in your
   shell environment or an untracked `.env`.

## Build

Produce the distributable wheel and source archive (these are what get published to
PyPI):

```bash
pip install build
python -m build     # writes dist/*.whl and dist/*.tar.gz
```

## Documentation

- [docs/sdk-guide.md](./docs/sdk-guide.md) — how the SDK works, the two-token model,
  verification logic, sentinels, authentication, DPoP, caching, and the error hierarchy.
- [docs/payment-flow.md](./docs/payment-flow.md) — the end-to-end payment sequence.

## License

Apache-2.0
