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

Install this package with x402 and the extra for your web framework:

```bash
pip install fiat-extension-for-x402 "x402[fastapi]"   # or "x402[flask]"
```

Requires Python 3.10+ and `x402` 2.20 or later (below 3.0).

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

## Quick start (Flask)

Flask's middleware is synchronous, so use the synchronous x402 objects:

```python
from flask import Flask
from x402 import x402FacilitatorSync, x402ResourceServerSync
from x402.http.middleware.flask import payment_middleware

# signer, verifier and routes as above
facilitator = register_exact_agentic_commerce_facilitator(x402FacilitatorSync(), verifier=verifier)
server = register_exact_agentic_commerce_server(x402ResourceServerSync(facilitator), signer=signer)

app = Flask(__name__)


@app.get("/weather")
def weather() -> dict[str, object]:
    return {"temperature_f": 58}


payment_middleware(app, routes, server)
```

Runnable versions of both, plus a Lambda deployment, are in [examples/](examples/).

## Quote signing

The seller signs every quote with its own key. The listing is registered with
either the KMS key or a JWKS URL, and the facilitator is configured with the
same key.

| Signer | Key | Facilitator resolver |
|---|---|---|
| `KmsQuoteSigner` | An AWS KMS key. The private key never leaves KMS. | `KmsSellerKeyResolver(key_arn, region)` |
| `LocalQuoteSigner` | A private key you manage (PEM file, secrets manager, HSM export). | `JwksSellerKeyResolver(jwks_url)` |

To keep the key elsewhere, for example in an HSM that signs remotely, implement
the `QuoteSigner` protocol (`sign_quote(payload) -> str` and
`get_service_url() -> str`).

The signer's `service_url` becomes the quote token's `iss` claim and must be the
seller URL registered for the listing.

### An AWS KMS key

Create an asymmetric signing key:

```bash
aws kms create-key --key-spec ECC_NIST_P384 --key-usage SIGN_VERIFY \
  --description "x402 quote signing"
aws kms create-alias --alias-name alias/my-quote-key --target-key-id <key-id>
```

`ECC_NIST_P384` with `ECDSA_SHA_384` is the default. `ECC_NIST_P256` and
`ECC_NIST_P521` work with `algorithm="ECDSA_SHA_256"` or `"ECDSA_SHA_512"`.

IAM permissions on the key:

| Who | Action |
|---|---|
| The seller (`KmsQuoteSigner`) | `kms:Sign` |
| The facilitator (`KmsSellerKeyResolver`) | `kms:GetPublicKey` |

The JWS `kid` is taken from the key ARN (the alias name, or `key/<id>`) unless
`kid=` is set.

### Your own key with a JWKS URL

Sign with your own private key and publish the public key at
`https://<seller>/.well-known/jwks.json`, the JWKS URL registered for the
listing:

```python
from pathlib import Path

from fiat_extension_x402 import JwksSellerKeyResolver, LocalQuoteSigner, jwks_document

# 1. Load the key. The algorithm follows the key: P-256/P-384/P-521, or RSA
#    of at least 2048 bits.
signer = LocalQuoteSigner.from_pem(
    Path("quote-key.pem").read_bytes(),
    kid="quote-key-2026-10",
    service_url="https://api.example.com",
)


# 2. Serve the public key. Leave this route out of the payment routes.
@app.get("/.well-known/jwks.json")
def jwks() -> dict[str, list[dict[str, object]]]:
    return jwks_document(signer.public_jwk)


# 3. Point the facilitator at the JWKS.
verifier = AgenticCommerceVerifier(
    seller_key_resolver=JwksSellerKeyResolver("https://api.example.com")
)
```

Create a P-384 key with OpenSSL:

```bash
openssl ecparam -name secp384r1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out quote-key.pem
```

Every key needs a unique `kid`: verifiers pick the key named in the quote's
header. To rotate, publish both keys (`jwks_document(new.public_jwk,
old.public_jwk)`), switch the signer to the new key, and remove the old key once
its quotes have expired. Facilitators cache the JWKS for up to an hour, so
publish a new key at least an hour before signing with it.

`jwks_document` accepts only keys verifiers will use: EC on P-256, P-384 or
P-521, or RSA of at least 2048 bits, each with a unique `kid` and an `alg` that
matches the key. It parses the key material and rejects anything malformed or
containing private key fields. Never publish the PEM.

See [examples/jwks_seller.py](examples/jwks_seller.py).

### Local development and tests

For tests, sign with a generated key and give the facilitator the public key
directly, with no JWKS endpoint:

```python
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

from fiat_extension_x402 import LocalQuoteSigner, StaticSellerKeyResolver

private_key = ec.generate_private_key(ec.SECP256R1())
public_jwk = ECAlgorithm.to_jwk(private_key.public_key(), as_dict=True) | {
    "alg": "ES256",
    "kid": "dev",
}
signer = LocalQuoteSigner(private_key, public_jwk, "http://localhost:8000")
verifier = AgenticCommerceVerifier(seller_key_resolver=StaticSellerKeyResolver(public_jwk))
```

## Configuration

### Product ID

Set each route's `pay_to` to the seller's **AWS Marketplace product ID**. The
server scheme signs it into the quote as `payTo` and as `settlement.product_id`,
which the payment service requires to settle against the listing. On the wire,
`payTo` is replaced by a placeholder; the signed quote carries the real value.

Other quote details come from the route's `extra`:

```python
PaymentOption(
    scheme="exact",
    network="aws:base",
    pay_to="prod-abc123",            # AWS Marketplace product ID
    price="$0.01",                   # at most 8 decimal places
    extra={
        "description": "Current weather",
        "dimensions": {"calls": 1},
        "settlement": {"mode": "immediate"},   # product_id is added for you
        "reference": "weather-v1",
    },
)
```

### Seller key resolution

The facilitator verifies each quote with the seller's own public key. The key is
always configured, never discovered from the token:

| Resolver | Key source |
|---|---|
| `KmsSellerKeyResolver(kms_key_arn, region)` | `kms:GetPublicKey` (cached for one hour) |
| `JwksSellerKeyResolver(jwks_url)` | `{jwks_url}/.well-known/jwks.json` (cached for one hour) |
| `StaticSellerKeyResolver(public_jwk)` | A JWK the facilitator already holds |

### Payment token verification

`AgenticCommerceVerifier` accepts:

- `payment_token_jwks_url`: base URL of the service's signing keys (defaults to production).
- `jwks_request_headers`: extra headers for that request, for example an access
  header issued during onboarding.

### DPoP

When a payment token is bound to a key (`cnf.jkt`), the request must carry a
`DPoP` header (RFC 9449) proving possession of that key for this method, URL and
payment token. The server scheme checks this before verification. To reject
replayed proofs, pass a `DPoPNonceStore` shared by all instances of the seller:

```python
register_exact_agentic_commerce_server(server, signer=signer, dpop_nonce_store=store)
```

`dpop_max_age_seconds` (default 60) limits how old a proof may be.

## Failure reasons

A rejected payment gets another `402`. The reason is in the response's
`PAYMENT-REQUIRED` header (`error`) and in the facilitator's verify result:

| Reason | Meaning |
|---|---|
| `invalid_payment` | The payment token is not signed by the service, its issuer or audience is wrong, or the amount or currency differs from the route |
| `payment_expired` | The payment token has expired |
| `invalid_quote` | The quote is missing, is not the one the payment token was issued for, or is not signed by the seller's configured key |
| `quote_expired` | The quote has expired |
| `dpop_required` | The payment token is bound to a key but the request has no valid `DPoP` header |
| `dpop_invalid` | The `DPoP` proof does not match the key, method, URL or token, is too old, or was replayed |

## Running the facilitator separately

The facilitator scheme works with any x402 facilitator, so it can also run as a
standalone service that sellers call through `x402.http.HTTPFacilitatorClient`:

```python
from x402 import x402Facilitator
from fiat_extension_x402 import register_exact_agentic_commerce_facilitator

facilitator = register_exact_agentic_commerce_facilitator(x402Facilitator(), verifier=verifier)
```

## Versioning

This package follows [semantic versioning](https://semver.org). Breaking changes
to the public API (everything in `fiat_extension_x402.__all__`) only ship in a
new major version. See [CHANGELOG.md](CHANGELOG.md).

## Development

```bash
uv sync --extra dev
uv run pytest --cov=fiat_extension_x402 --cov-branch
uv run ruff check . && uv run ruff format --check .
uv run mypy --strict src tests
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.
