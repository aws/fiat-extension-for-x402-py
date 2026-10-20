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
    S->>S: after_verify: reject a replayed DPoP proof, record its jti
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
| `price` | `{"amount": "0.01", "currency": "USD"}` (at most 8 decimal places) |
| `payTo` | The seller's AWS Marketplace product ID (route `pay_to`) |
| `settlement` | `extra.settlement` plus `product_id` (the route `pay_to`); required by the payment service |
| `reference` | `extra.reference`, default `RESOURCE` |
| `description`, `dimensions`, `support`, `terms` | Copied from `extra` when present |

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
is the hash of the payment token; and it is no older than 60 seconds. The payment
token is not verified yet, so the nonce store is not used here.

Once the facilitator has accepted the token, the seller scheme (`after_verify`)
checks, with a nonce store, that the proof is still fresh and its `jti` has not
been seen, and records the `jti`. A replayed proof is refused with `dpop_invalid`
after the facilitator call, and x402 core reports the verified payment as
canceled (`after_verify_aborted`); nothing is settled.

The facilitator (`AgenticCommerceVerifier`) checks that:

1. before any network call: the payment token uses an allowed algorithm and
   names a key (`kid`), its `iss` is the service, it has not expired, and its
   `quote_token` equals the quote in `accepted`;
2. the payment token is signed by the service (its JWKS, cached for 60 seconds)
   and carries a `payment_id`;
3. the quote is signed by the seller's configured key;
4. the payment token's `aud` is the quote's `iss`, and the quote has not expired;
5. the quote's price equals the route's amount and currency, and its `iss`,
   `aud`, `payTo`, `settlement` and `reference` equal those of the route's
   current quote.

Failures return `invalid_payment`, `payment_expired`, `invalid_quote` or
`quote_expired`; DPoP failures abort with `dpop_required` or `dpop_invalid`.

Settling is a no-op and nothing records the payment, so the same payment is
accepted again until it expires. The seller records each `payment_id` to accept
it once; see [security.md](security.md#payment-replay).
