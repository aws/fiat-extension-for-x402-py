# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Agent Pay server-side scheme for resource services.

Resource services use :func:`enhance_payment_requirements` to attach a signed
quote token to an HTTP 402 response.
"""

from __future__ import annotations

from fiat_extension_x402.server.scheme import enhance_payment_requirements

__all__ = ["enhance_payment_requirements"]
