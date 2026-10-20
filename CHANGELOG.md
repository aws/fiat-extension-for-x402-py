# Changelog

All notable changes to this project are documented here. The project follows
[semantic versioning](https://semver.org).

## Unreleased

### Breaking changes

- `verify_payment_token` and `verify_quote_token` are removed. They checked a
  token's signature but not its issuer, audience or quote, and accepted tokens
  without an expiry. Verify payments with `AgenticCommerceVerifier`.
- `AgenticCommerceVerifier` refuses a payment token without a `kid` or a
  `payment_id`.

### Security

- `AgenticCommerceVerifier` checks a payment token's algorithm, key id, issuer,
  expiry and quote before fetching the payment service's JWKS, so a forged or
  stale token costs no network call. The JWKS is cached for 60 seconds, a token
  naming an unknown key refetches it at most every 30 seconds, concurrent
  verifications share one fetch, and JWKS responses over 64 KiB are refused.
- The `exact` facilitator scheme requires the paid quote to match the route's
  current quote on `iss`, `aud`, `payTo`, `settlement` and `reference`, so a
  quote for another route, product or service sharing the signing key is
  refused. `AgenticCommerceVerifier.verify` takes the route's quote as
  `route_quote_token`.
- `docs/security.md` documents that verification is stateless and that sellers
  must record each `payment_id` to accept a payment once.

## 1.0.0

Initial release: the seller and facilitator roles of AWS Marketplace Agentic
Commerce on x402, for Python 3.10 or later and x402 2.20 or later.

- `exact` payment scheme for AWS Marketplace Agentic Commerce networks
  (`aws:*`):
  - `ExactAgenticCommerceServerScheme` prices routes in fiat, signs a quote
    token (including the AWS Marketplace product ID) into every `402`, and
    checks DPoP proofs.
  - `ExactAgenticCommerceFacilitatorScheme` and `AgenticCommerceVerifier`
    verify payment tokens against the quote they pay for.
  - `register_exact_agentic_commerce_server` and
    `register_exact_agentic_commerce_facilitator` register them on x402 core
    objects. Routes are protected with x402's own FastAPI and Flask middleware.
- Quote signers: `KmsQuoteSigner` (AWS KMS) and `LocalQuoteSigner` (a key you
  manage, including `LocalQuoteSigner.from_pem`), plus the `QuoteSigner`
  protocol for other key stores. `LocalQuoteSigner.from_pem` rejects RSA keys
  marked for RSA-PSS only.
- Seller key resolvers: `KmsSellerKeyResolver`, `JwksSellerKeyResolver` and
  `StaticSellerKeyResolver`. The seller's key is always configured, never
  discovered from the quote token.
- `jwks_document` builds and validates the JWKS a seller serves at
  `/.well-known/jwks.json`. RSA quote keys must be at least 2048 bits.
- Route prices as a string (`"$0.01"`), a number, or an `AssetAmount` /
  `{"amount", "asset"}` dict, where `amount` is a plain decimal string with at
  most 8 decimal places and `asset` is `iso4217:` and an upper-case three-letter
  code. Prices accept ASCII digits only. Any other price is a `ValidationError`
  that shows only the amount and asset, never a signed quote.
- DPoP replay protection: the server scheme records a proof's `jti` in the
  `DPoPNonceStore` only after the facilitator has accepted the payment token (in
  the `after_verify` scheme hook), until the second after the proof stops being
  accepted (`iat` + maximum age + 5 seconds of clock skew + 1). A forged token
  adds nothing to the store. A replayed proof is refused with `dpop_invalid`
  after the facilitator call; the seller's `on_after_verify` hooks run, and
  `on_verified_payment_canceled` is called with `after_verify_aborted`, for a
  payment an earlier request may already have completed, so that reason alone
  must not void or refund it. Nothing is settled. With a nonce store, a
  transport context passed to `verify_payment` by the caller must support weak
  references; x402's `HTTPTransportContext` does.
- An error for a JWK that cannot be imported names the key by its `kid` and
  never includes the key's members.
