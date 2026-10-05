# Examples

| Example | What it shows |
|---|---|
| [fastapi_seller.py](fastapi_seller.py) | A FastAPI seller using x402's FastAPI middleware, a KMS quote signer and an in-process facilitator |
| [flask_seller.py](flask_seller.py) | The same seller on Flask, with x402's synchronous objects |
| [jwks_seller.py](jwks_seller.py) | A FastAPI seller that signs with its own PEM key and serves its JWKS at `/.well-known/jwks.json` |
| [lambda_seller/](lambda_seller/) | The FastAPI seller on AWS Lambda behind a Function URL, with a CloudFormation template and `deploy.sh` |

Deploy the Lambda seller to your own account:

```bash
AWS_PROFILE=my-dev ./examples/lambda_seller/deploy.sh my-seller-stack prod-example123
```

The stack creates the KMS quote-signing key, the function and its URL. Delete it
with `aws cloudformation delete-stack --stack-name my-seller-stack` (the KMS key
is scheduled for deletion).
