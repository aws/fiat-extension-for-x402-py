# Security Guide

This page describes the protections in `fiat-extension-for-x402` and what a
seller must do to keep them effective. To report a vulnerability, see the
[AWS vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/).

## Payment replay

**Verification is stateless, and the SDK does not stop a payment from being
used twice.** `AgenticCommerceVerifier` checks signatures, claims and the quote;
it keeps no record of the payments it has accepted, and the facilitator's
`settle` is a no-op, because the payment service captures a payment when it
issues the payment token. So the same `PAYMENT-SIGNATURE` header is accepted on
every request until the earlier of the payment token's and the quote's `exp`
(300 seconds by default). Anyone who sees the header (in logs, a proxy or a
trace) can present it again; DPoP limits this to the buyer's key only for tokens
bound with `cnf.jkt`, and only when a `dpop_nonce_store` is configured.

The SDK cannot hold that record for you: only a store shared by every instance
of the seller rejects a replay sent to another instance, and the SDK cannot
choose or reach your storage. This is the same model as x402's
[`exact` scheme on Solana](https://github.com/coinbase/x402/blob/main/specs/schemes/exact/scheme_exact_svm.md#duplicate-settlement-mitigation-recommended),
where the merchant or facilitator keeps the record of payloads already settled.

What the seller must do:

- **Record each `payment_id` before serving the request.** Every accepted
  payment token carries a `payment_id` (`VerificationResult.payment_id`, and the
  `transaction` of the settle response and the `PAYMENT-RESPONSE` header).
  Record it with an atomic check-and-set (for example a DynamoDB conditional
  put, or Redis `SET NX`) and refuse the request when it was already recorded.
- **Take the id from the verified payment token only.** Use the `payment_id`
  claim of the payment token the facilitator verified (`payload["paymentToken"]`).
  Never key on a `paymentId` the buyer sends anywhere else in the payment
  payload: the buyer sets it and the SDK does not check it, so a replay with a
  new value there passes the check.
- **Share the store** across every instance of the seller. A store per process
  rejects replays to that process only.
- **Keep each id** until `max(payment token exp, quote exp)` plus your clock
  skew allowance. After that, both checks reject the token anyway.

For example, with an x402 `on_after_verify` hook, which runs once the payment
token is verified and refuses the request when it returns an `AbortResult`:

```python
import jwt
from x402.schemas import AbortResult


def accept_each_payment_once(context):
    # The payment token the facilitator verified; never payload["paymentId"],
    # which the buyer sets.
    token = context.payment_payload.payload["paymentToken"]
    claims = jwt.decode(token, options={"verify_signature": False})
    quote = jwt.decode(claims["quote_token"], options={"verify_signature": False})
    expires_at = max(claims["exp"], quote["exp"]) + 60
    # claim_once: your shared store's atomic "record unless present".
    if not claim_once(claims["payment_id"], expires_at):
        return AbortResult(reason="payment_replayed", message="Payment already used")
    return None


server.on_after_verify(accept_each_payment_once)
```

## Keys

- **Seller keys are configured, never discovered.** `AgenticCommerceVerifier`
  requires a seller key resolver (`KmsSellerKeyResolver`,
  `JwksSellerKeyResolver` or `StaticSellerKeyResolver`) and verifies quotes only
  with that key. It never fetches a key from the quote's `iss`, a `jku` or any
  other URL in a token.
- **Private keys stay private.** Prefer `KmsQuoteSigner`, where the key never
  leaves AWS KMS. With `LocalQuoteSigner`, load the PEM at startup from a
  mounted file or a secrets manager; never commit it, bake it into an image or
  hard-code it.
- **Rotation.** Give every key a unique `kid`, publish the next key at least an
  hour before signing with it (verifiers cache seller keys for an hour), and
  remove the old key once its quotes have expired.
- **Least privilege.** The seller needs `kms:Sign` on its KMS key; the
  facilitator needs only `kms:GetPublicKey`.

## Algorithms

Payment-token and quote signatures are limited to `ALLOWED_ALGORITHMS`: RS256,
ES256, ES384 and ES512. DPoP proofs may use ES256, ES384, ES512, RS256 or PS256.
`none` and the HMAC algorithms are always refused, which prevents
algorithm-confusion forgeries.

## Payment verification

A payment token is accepted only when it is signed by the payment service, has
the expected issuer, a key id and a `payment_id`, has not expired, embeds exactly
the quote the buyer accepted, and that quote is signed by the seller's
configured key, addressed to the seller (`aud`), unexpired, at the route's price
and currency, for the route's scheme and network (when the quote names them),
and for the route: the `exact` facilitator scheme requires its `iss`, `aud`,
`payTo` (the product ID), `settlement`, `reference`, `scheme` and `network` to
equal those of the quote the seller signs for the route now. Every failure rejects
the payment; nothing fails open.

- The token's algorithm, key id, issuer, expiry and quote are checked before
  any network call, so a forged or stale token costs nothing to refuse.
- The quote comparison is constant-time (`secure_compare`).
- The payment service's JWKS is cached for 60 seconds, so a revoked service key
  stops being accepted within a minute. A token naming a key the cache lacks
  refetches it at most every 30 seconds, and concurrent verifications share one
  fetch.
- JWKS requests time out after 10 seconds, refuse responses over 64 KiB, and do
  not follow redirects, so `jwks_request_headers` never reach another host; they
  are never sent to a seller JWKS URL.
- `decode_quote_token` decodes without verifying, for inspection only. Accept
  payments only through `AgenticCommerceVerifier`.

## DPoP

DPoP (RFC 9449) binds a payment token to the buyer's key (`cnf.jkt`), so a
stolen bound token is useless without that key. The `exact` server scheme
requires a matching `DPoP` proof for this request's method, URL and payment
token, issued within `dpop_max_age_seconds` (default 60, plus 5 seconds of
skew). To reject replayed proofs, pass a `dpop_nonce_store` shared by every
instance of the seller; see the README. DPoP does not replace the payment
record above: the buyer can sign a fresh proof for every request.

## Transport

- Serve the seller, its JWKS and every facilitator over HTTPS.
- `verify` blocks while it fetches keys, at most about once a minute. x402's
  `x402Facilitator` calls it on the event loop, so an async seller pauses for
  that fetch.
- The package does not log tokens, keys or credentials. A JWK that cannot be
  imported is reported as `JWK <kid>: invalid key material`, never with its
  members.
