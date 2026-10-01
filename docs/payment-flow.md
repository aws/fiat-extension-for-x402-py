# Payment flow

```mermaid
sequenceDiagram
    participant B as Buyer
    participant S as Seller (x402 middleware + ExactAgenticCommerceServerScheme)
    participant F as Facilitator (ExactAgenticCommerceFacilitatorScheme)
    participant P as AWS Marketplace Agentic Commerce

    B->>S: GET /resource
    S->>S: parse_price, sign quote token (enhance_payment_requirements)
    S-->>B: 402 PAYMENT-REQUIRED: exact / aws:base / extra.quoteToken
    B->>P: request payment for the quote
    P-->>B: payment token (signed by the service; payment captured)
    B->>S: GET /resource + PAYMENT-SIGNATURE {accepted, payload.paymentToken} [+ DPoP]
    S->>S: match accepted against the route's requirements (quoteToken excluded)
    S->>S: before_verify: DPoP proof, if the token is DPoP-bound
    S->>F: verify(payload, requirements)
    F->>P: fetch payment token JWKS
    F-->>S: valid
    S->>S: run the route handler
    S->>F: settle (no-op)
    S-->>B: 200 + PAYMENT-RESPONSE {transaction: payment id}
```

## 402 requirements

```json
{
  "scheme": "exact",
  "network": "aws:base",
  "asset": "iso4217:USD",
  "amount": "0.01",
  "payTo": "urn:x402:agentic-commerce:see-quote",
  "maxTimeoutSeconds": 300,
  "extra": { "quoteToken": "<JWS signed by the seller>" }
}
```

`payTo` is a placeholder: the signed quote carries the real payee. `amount` is a
decimal fiat amount, not atomic units.

## Quote token claims

| Claim | Value |
|---|---|
| `iss` | The seller's service URL |
| `aud` | `aws:marketplace` |
| `iat`, `exp` | Issue time and expiry (`maxTimeoutSeconds`, default 300) |
| `jti` | Unique id |
| `price` | `{"amount": "0.01", "currency": "USD"}` |
| `payTo` | The seller's payee identifier |
| `reference` | `extra.reference`, default `RESOURCE` |
| `description`, `dimensions`, `settlement`, `support`, `terms` | Copied from `extra` when present |

## Payment payload

```json
{
  "x402Version": 2,
  "accepted": { "...": "the requirements the buyer paid for" },
  "payload": { "paymentToken": "<JWS signed by the service>" }
}
```

## Checks

The resource server (x402 core) checks that `accepted` matches the route's own
requirements: scheme, network, amount, asset, payTo, maxTimeoutSeconds and
`extra`, except the quote token, which is signed afresh for each 402.

The seller scheme (`before_verify`) checks, for a DPoP-bound payment token
(`cnf.jkt`): a `DPoP` header is present; its key thumbprint equals `cnf.jkt`; it
is signed with an asymmetric algorithm; `htm` and `htu` match the request; `ath`
is the hash of the payment token; it is no older than 60 seconds; and, with a
nonce store, its `jti` has not been seen.

The facilitator (`AgenticCommerceVerifier`) checks that:

1. the payment token is signed by the service (its JWKS) with an allowed algorithm;
2. its `iss` is the service and it has not expired;
3. its `quote_token` equals the quote in `accepted`;
4. the quote is signed by the seller's configured key;
5. the payment token's `aud` is the quote's `iss`, and the quote has not expired;
6. the quote's price equals the route's amount and currency.

Failures return `invalid_payment`, `payment_expired`, `invalid_quote` or
`quote_expired`; DPoP failures abort with `dpop_required` or `dpop_invalid`.
