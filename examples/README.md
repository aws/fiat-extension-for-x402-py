# Examples

Runnable examples for the Agent Pay x402 Python SDK.

| File | What it shows | Needs AWS? |
|------|---------------|------------|
| [`end_to_end_demo.py`](./end_to_end_demo.py) | The full seller → Agent Pay → buyer → verify → settle round-trip, in-process | No |
| [`local_flow/`](./local_flow/) | The same flow across three real localhost processes (mock Agent Pay + seller + buyer) | No |
| [`fastapi_app.py`](./fastapi_app.py) | Protecting FastAPI routes with the payment middleware | KMS key to enable paid routes |
| [`flask_app.py`](./flask_app.py) | Protecting Flask routes with the payment middleware | KMS key to enable paid routes |
| [`live_e2e_smoke.py`](./live_e2e_smoke.py) | One-shot smoke test against a live seller + real Agent Pay service | AWS credentials + a live seller endpoint |

Install the package with its dev extras first (the demo uses `respx`):

```bash
pip install -e ".[dev]"
```

## End-to-end demo (no network, no credentials)

`end_to_end_demo.py` runs the entire payment flow in a single process. It signs
a quote token with a local key, mints a matching payment token to stand in for
the Agent Pay service, and verifies it through `AgentPayFacilitatorClient` —
with the Agent Pay and seller JWKS endpoints served from in-memory mocks. No AWS
account, KMS key, or live service is required.

```bash
python examples/end_to_end_demo.py
```

It prints each step of the flow and ends with the seller delivering the
resource. This is the runnable companion to the in-process integration tests
under [`tests/integration`](../tests/integration).

## FastAPI / Flask middleware

Both web examples protect a `/api/premium` and a `/api/generate` route while
leaving `/api/free` open. Configuration is read from the environment so no
secrets are committed. With no `AGENTPAY_KMS_KEY_ARN` set, the app still starts
with payment protection disabled, so you can smoke-test the free route without
AWS access.

```bash
export AGENTPAY_KMS_KEY_ARN="arn:aws:kms:us-east-1:123456789012:key/<key-id>"
export AGENTPAY_REGION="us-east-1"                 # optional, default us-east-1
export AGENTPAY_SERVICE_URL="https://api.example.com"
export AGENTPAY_BASE_URL="https://prod.agentpay.marketplace.aws.dev"  # optional
export AGENTPAY_ID="my-agent-pay-id"               # optional
export AGENTPAY_PAY_TO="seller-agent-pay-id"
```

The KMS key must be an asymmetric EC signing key (`ECC_NIST_P384` / ES384) and
the calling identity must be allowed to call `kms:Sign` on it.

### FastAPI

```bash
pip install -e ".[dev,fastapi]"
uvicorn examples.fastapi_app:app --port 8000

curl localhost:8000/api/free        # 200 — no payment required
curl -i localhost:8000/api/premium  # 402 — quote token in the body (when configured)
```

### Flask

```bash
pip install -e ".[dev,flask]"
flask --app examples.flask_app run --port 5001

curl localhost:5001/api/free        # 200 — no payment required
curl -i localhost:5001/api/premium  # 402 — quote token in the body (when configured)
```

After a buyer completes a payment and retries with an `X-Payment` header, the
verified payment details are available on `request.state.agent_pay_payment`
(FastAPI) or `g.agent_pay_payment` (Flask).

## Live smoke test

`live_e2e_smoke.py` is a single-file, one-shot check of the full buyer flow
against a **real** seller endpoint and the live Agent Pay service: GET the seller
(expect 402), select the `agent-pay` offer on an `aws:*` network from `accepts`,
register that network on an x402 client and call `create_payment_payload` (core
routes the offer to the Agent Pay scheme, which calls CreateAgentPayment), then
retry with the base64-encoded payment payload under the standard
`PAYMENT-SIGNATURE`/`X-PAYMENT` headers (expect 200). If the seller only
accepts a raw `Authorization: Bearer` token, the script still passes via that
fallback but flags the endpoint as misconfigured. It uses only the SDK and its
runtime dependencies — no dev extras — and reads its configuration from the
environment, so no endpoint or secret is hardcoded.

```bash
export AGENTPAY_QUOTE_URL="https://<seller-endpoint>/"   # required — returns HTTP 402
export AGENTPAY_BASE_URL="https://prod.agentpay.marketplace.aws.dev"  # optional
export AGENTPAY_REGION="us-east-1"                       # optional

python examples/live_e2e_smoke.py
```

Buyer AWS credentials come from the ambient environment (an active AWS profile or
`AWS_*` variables) for SigV4 signing. For the gated, multi-case live suite, see
[`tests/e2e/`](../tests/e2e) (`pytest -m e2e`); this script is the quick
hand-it-to-anyone version.

## See also

- [Top-level README](../README.md) — quickstart for each role
- [docs/sdk-guide.md](../docs/sdk-guide.md) — conceptual deep-dive
- [docs/payment-flow.md](../docs/payment-flow.md) — the payment sequence diagram
- [utils/](../utils/) — e2e test of the official AWS SDK (boto3) preview client
