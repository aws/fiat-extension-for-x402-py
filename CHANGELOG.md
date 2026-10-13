# Changelog

All notable changes to this project are documented here. The project follows
[semantic versioning](https://semver.org).

## 1.0.0

First public release.

- `exact` payment scheme for AWS Marketplace Agentic Commerce networks
  (`aws:*`), for x402 2.20 or later:
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
  protocol for other key stores.
- Seller key resolvers: `KmsSellerKeyResolver`, `JwksSellerKeyResolver` and
  `StaticSellerKeyResolver`. The seller's key is always configured, never
  discovered from the quote token.
- `jwks_document` builds and validates the JWKS a seller serves at
  `/.well-known/jwks.json`. RSA quote keys must be at least 2048 bits.
  `LocalQuoteSigner.from_pem` rejects RSA keys marked for RSA-PSS only.
- DPoP replay protection keeps a proof id in the `DPoPNonceStore` until the
  second after the proof stops being accepted (`iat` + maximum age + 5 seconds
  of clock skew + 1), so a store that evicts at that time never forgets a proof
  that would still be accepted.
- An error for a JWK that cannot be imported names the key by its `kid` and
  never includes the key's members.
