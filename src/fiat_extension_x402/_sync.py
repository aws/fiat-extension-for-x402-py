# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Run a coroutine from synchronous code.

x402 core's scheme protocols are synchronous — even the async
``x402ResourceServer`` calls ``enhance_payment_requirements`` without awaiting
it. This SDK's signers are async (``ServiceAgentPaySigner.sign_quote``), because
KMS signing offloads a blocking boto3 call with ``asyncio.to_thread``. The
scheme adapters therefore need to drive an async signer from a sync method.

Internal module: not part of the public API.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
from collections.abc import Coroutine
from typing import Any, TypeVar

_T = TypeVar("_T")


def run_coroutine_sync(coro: Coroutine[Any, Any, _T]) -> _T:
    """Run ``coro`` to completion and return its result, from sync code.

    Handles both calling contexts:

    * **No running event loop** (Flask, a script, a sync test) — uses
      :func:`asyncio.run` directly.
    * **Inside a running event loop** (a FastAPI request handler, an async
      test) — ``asyncio.run`` would raise, so the coroutine is handed to a
      short-lived worker thread with its own loop and awaited there. That
      thread's loop is independent, so a signer using ``asyncio.to_thread``
      still works.

    :param coro: The coroutine to run. Always consumed exactly once.
    :returns: Whatever the coroutine returns.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        # No loop on this thread: we own the execution context.
        return asyncio.run(coro)

    # A loop is already running on this thread; run the coroutine on its own
    # loop in a worker thread and block until it finishes.
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        return executor.submit(asyncio.run, coro).result()


__all__ = ["run_coroutine_sync"]
