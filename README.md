# Fiat Extension for x402 (Python)

Accept fiat payments for HTTP APIs through the [x402](https://x402.org) protocol
with **AWS Marketplace Agentic Commerce**.

This package plugs into the [x402 Python SDK](https://pypi.org/project/x402/). It
provides the `exact` payment scheme for AWS Marketplace Agentic Commerce networks
(`aws:*`), for the two roles a seller runs:

| x402 role | Class | What it does |
|---|---|---|
| Resource server (seller) | `ExactAgenticCommerceServerScheme` | Prices routes in fiat, adds a signed **quote token** to every `402 Payment Required` response, and checks DPoP proofs |
| Facilitator | `ExactAgenticCommerceFacilitatorScheme` | Verifies the **payment token** a buyer presents against the quote it pays for |

Use x402's own HTTP middleware (FastAPI, Flask) to protect routes. This package
does not provide middleware or buyer-side code.

## How a payment works

1. A buyer requests a protected route without paying. The middleware answers
   `402` with `exact` payment requirements on network `aws:base`, priced in
   `iso4217:USD`, carrying a quote token signed by the seller.
2. The buyer obtains a payment token for that quote from AWS Marketplace
   Agentic Commerce, which signs it and captures the payment.
3. The buyer retries with the payment token. The facilitator verifies it and the
   route runs. Settlement is a no-op: the payment was already captured.

See [docs/payment-flow.md](docs/payment-flow.md) for the full sequence and the
checks performed.

## Install

```bash
pip install "fiat-extension-for-x402[fastapi]"   # or [flask]
```

Requires Python 3.10+ and `x402` 2.20 or later.

## Quick start (FastAPI)

```python
from fastapi import FastAPI
from x402 import x402Facilitator, x402ResourceServer
from x402.http.middleware.fastapi import payment_middleware
from x402.http.types import PaymentOption, RouteConfig

from fiat_extension_x402 import (
    AgenticCommerceVerifier,
    KmsQuoteSigner,
    KmsQuoteSignerConfig,
    KmsSellerKeyResolver,
    register_exact_agentic_commerce_facilitator,
    register_exact_agentic_commerce_server,
)

KEY_ARN = "arn:aws:kms:us-east-1:111122223333:alias/my-quote-key"

# Seller: signs quotes with a KMS key (ECC_NIST_P384, SIGN_VERIFY).
signer = KmsQuoteSigner(
    KmsQuoteSignerConfig(key_arn=KEY_ARN, region="us-east-1", service_url="https://api.example.com")
)

# Facilitator: verifies payment tokens, here in the seller's own process.
verifier = AgenticCommerceVerifier(seller_key_resolver=KmsSellerKeyResolver(KEY_ARN, "us-east-1"))
facilitator = register_exact_agentic_commerce_facilitator(x402Facilitator(), verifier=verifier)
server = register_exact_agentic_commerce_server(x402ResourceServer(facilitator), signer=signer)

routes = {
    "GET /weather": RouteConfig(
        accepts=PaymentOption(scheme="exact", network="aws:base", pay_to="prod-example123", price="$0.01"),
        description="Current weather",
    ),
}

app = FastAPI()


@app.get("/weather")
def weather() -> dict[str, object]:
    return {"temperature_f": 58}


app.middleware("http")(payment_middleware(routes, server))
```

Flask is the same with `x402ResourceServerSync`, `x402FacilitatorSync` and
`x402.http.middleware.flask.payment_middleware(app, routes, server)`. See
[examples/](examples/).

## Configuration

### Quote signing

| Signer | Use |
|---|---|
| `KmsQuoteSigner` | Production. The private key never leaves AWS KMS. Supports `ECDSA_SHA_256/384/512` (default `ECDSA_SHA_384`). |
| `LocalQuoteSigner` | Development and tests. Holds the private key in memory. |

The signer's `service_url` becomes the quote token's `iss` claim and must be the
seller URL registered for the listing.

### Seller key resolution

The facilitator verifies each quote with the seller's own public key. The key is
always configured, never discovered from the token:

| Resolver | Key source |
|---|---|
| `KmsSellerKeyResolver(kms_key_arn, region)` | `kms:GetPublicKey` (cached for one hour) |
| `JwksSellerKeyResolver(jwks_url)` | `{jwks_url}/.well-known/jwks.json` (cached for one hour) |
| `StaticSellerKeyResolver(public_jwk)` | A JWK the seller already holds |

### Payment token verification

`AgenticCommerceVerifier` accepts:

- `payment_token_jwks_url`: base URL of the service's signing keys (defaults to production).
- `jwks_request_headers`: extra headers for that request, for example an access
  header issued during onboarding.

### DPoP

When a payment token is bound to a key (`cnf.jkt`), the request must carry a
`DPoP` header (RFC 9449) proving possession of that key for this method, URL and
payment token. The server scheme checks this before verification; pass
`dpop_nonce_store=` to reject replayed proofs.

## Running the facilitator separately

The facilitator scheme works with any x402 facilitator, so it can also run as a
standalone service that sellers call through `x402.http.HTTPFacilitatorClient`:

```python
from x402 import x402Facilitator
from fiat_extension_x402 import register_exact_agentic_commerce_facilitator

facilitator = register_exact_agentic_commerce_facilitator(x402Facilitator(), verifier=verifier)
```

## Development

```bash
uv venv && uv pip install -e ".[dev]"
.venv/bin/pytest --cov=fiat_extension_x402 --cov-branch
.venv/bin/ruff check . && .venv/bin/ruff format --check .
.venv/bin/mypy --strict src tests
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.
