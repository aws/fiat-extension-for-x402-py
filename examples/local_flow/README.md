# Local three-process flow

A runnable local setup that exercises the full Agent Pay x402 flow across three
processes on localhost — no AWS account, no live service. It is the multi-process
companion to [`../end_to_end_demo.py`](../end_to_end_demo.py) (which runs the same
flow in a single process with mocked HTTP).

| Process | File | Port | Role |
|---------|------|------|------|
| Mock Agent Pay | [`mock_agent_pay_server.py`](./mock_agent_pay_server.py) | 3001 | Stands in for the AWS Marketplace Agent Pay Service: mints/signs payment tokens, serves its JWKS |
| Seller service | [`seller_service.py`](./seller_service.py) | 3002 | Protected resource server: returns 402 + signed quote, verifies payment, serves the resource |
| Buyer client | [`buyer_client.py`](./buyer_client.py) | — | Uses the SDK's `AgentPayClient` to pay and fetch the protected resource |

## What it demonstrates

- **402 → pay → retry**: the buyer hits a protected route, gets `402` with a
  signed quote token, creates a payment, and retries with an `x402` Authorization
  header to get `200` + the resource.
- **Real SDK on every leg**: the seller drives `AgentPayResourceServer` /
  `AgentPayFacilitatorClient`; the buyer uses `AgentPayClient` with SigV4 signing.
  Only the Agent Pay *provider* is a mock.
- **Real cryptographic verification**: the seller signs quote tokens with a local
  ES384 key and the mock signs payment tokens with its own ES384 key. Verification
  fetches each party's public JWKS over HTTP and checks both signatures — nothing
  is faked at the crypto layer.
- **Payment lookup**: the buyer calls `ListAgentPayments` to read its payments back.

## Run it

Install the package with its dev extras (the servers use Flask, which ships in
the `flask` extra; `dev` covers the rest):

```bash
pip install -e ".[dev,flask]"
```

Then start the three processes — **mock first, seller second, client last**.

```bash
# Terminal 1 — mock Agent Pay (port 3001)
python examples/local_flow/mock_agent_pay_server.py

# Terminal 2 — seller service (port 3002)
python examples/local_flow/seller_service.py

# Terminal 3 — buyer client (runs once and exits)
python examples/local_flow/buyer_client.py
```

Expected client output:

```
── GET /foo ───────────────────────────────
  [buyer] first GET -> 402 PAYMENT REQUIRED
  [buyer] quote: 0.15 iso4217:USD
  [buyer] created payment awsmp-...
  [buyer] paid GET  -> 200 OK
  [buyer] resource: Hello from /foo!  (paidBy=111122223333)
...
✅  All done — payments created, verified, and served.
```

You can also poke the seller directly with `curl`:

```bash
curl localhost:3002/health          # 200 — public
curl -i localhost:3002/foo          # 402 — quote token in the WWW-Authenticate header
```

## How the local wiring works

The plug-in middleware (`fiat_extension_x402.middleware.flask`) always verifies
against the **production** Agent Pay CDN, so this demo bypasses it and builds the
resource server directly. That lets the seller point its facilitator at the local
mock:

```python
server._facilitator = AgentPayFacilitatorClient(jwks_base_url="http://localhost:3001")
```

The buyer's `AgentPayClient` is pointed at the mock with `base_url`, and signs
with throwaway local credentials — the mock accepts any `AWS4-HMAC-SHA256`
request, so no real AWS identity is involved.
