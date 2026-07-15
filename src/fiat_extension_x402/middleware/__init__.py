# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Middleware sub-package for Agent Pay x402 payment protection.

Framework-specific middleware is imported from its own module to avoid
requiring the framework as a hard dependency. Import from the specific
submodule (e.g., ``fiat_extension_x402.middleware.flask``) or install the
corresponding extra (``pip install fiat-extension-for-x402[flask]``).
"""
