#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Deploy the example seller: build the Lambda package, deploy the stack, upload
# the code, and point the quote issuer at the Function URL.
#
#   AWS_PROFILE=my-dev ./deploy.sh <stack-name> <pay-to>
set -euo pipefail

STACK="${1:?stack name}"
PRODUCT_ID="${2:?AWS Marketplace product id}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BUILD="$(mktemp -d)"

echo "==> Building package"
(cd "$ROOT" && python -m build --wheel --outdir "$BUILD/dist" >/dev/null)
uv pip install -q --target "$BUILD/pkg" --python-platform aarch64-manylinux2014 \
  --python-version 3.12 --only-binary=:all: "$BUILD"/dist/*.whl "x402[fastapi]>=2.20,<3" \
  -r "$HERE/requirements.txt"
# The Lambda runtime provides boto3.
rm -rf "$BUILD"/pkg/{boto3,botocore,s3transfer}*
cp "$HERE/app.py" "$BUILD/pkg/"
(cd "$BUILD/pkg" && zip -qr9 "$BUILD/seller.zip" .)

echo "==> Deploying stack $STACK"
aws cloudformation deploy --stack-name "$STACK" --template-file "$HERE/template.yaml" \
  --capabilities CAPABILITY_IAM --parameter-overrides "ProductId=$PRODUCT_ID" --no-fail-on-empty-changeset

output() {
  aws cloudformation describe-stacks --stack-name "$STACK" \
    --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text
}
FUNCTION="$(output FunctionName)"
URL="$(output SellerUrl)"
URL="${URL%/}"

echo "==> Uploading code to $FUNCTION"
aws lambda update-function-code --function-name "$FUNCTION" --zip-file "fileb://$BUILD/seller.zip" >/dev/null
aws lambda wait function-updated --function-name "$FUNCTION"

echo "==> Setting quote issuer to $URL"
aws cloudformation deploy --stack-name "$STACK" --template-file "$HERE/template.yaml" \
  --capabilities CAPABILITY_IAM --parameter-overrides "ProductId=$PRODUCT_ID" "ServiceUrl=$URL" \
  --no-fail-on-empty-changeset
aws lambda wait function-updated --function-name "$FUNCTION"

echo "Seller: $URL/weather"
