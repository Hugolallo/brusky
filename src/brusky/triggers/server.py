"""FastAPI webhook server — receives Bitbucket PR events on POST /webhook/bitbucket."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog
from fastapi import FastAPI, HTTPException, Request, Response, status

from brusky.config import get_settings
from brusky.triggers.bitbucket import PR_EVENTS, parse_pr_payload, verify_signature
from brusky.triggers.dispatcher import ScanQueue, scan_worker

log = structlog.get_logger()


def build_app() -> FastAPI:
    """Construct and return the FastAPI application with all routes wired up."""
    queue = ScanQueue()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        settings = get_settings()
        worker = asyncio.create_task(
            scan_worker(
                queue=queue,
                access_token=settings.bitbucket_access_token,
                slack_webhook_url=settings.slack_webhook_url,
            )
        )
        log.info("brusky.server.started", port=8080)
        yield
        worker.cancel()
        try:
            await worker
        except asyncio.CancelledError:
            pass
        log.info("brusky.server.stopped")

    app = FastAPI(title="Brusky", version="0.1.0", lifespan=lifespan)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/webhook/bitbucket", status_code=status.HTTP_200_OK)
    async def bitbucket_webhook(request: Request) -> Response:
        settings = get_settings()

        # Validate HMAC signature
        body = await request.body()
        sig_header = request.headers.get("X-Hub-Signature", "")
        if not verify_signature(settings.bitbucket_webhook_secret, body, sig_header):
            log.warning("webhook.bitbucket.signature_invalid", sig=sig_header[:20])
            raise HTTPException(status_code=401, detail="Invalid signature")

        # Check event type
        event_key = request.headers.get("X-Event-Key", "")
        if event_key not in PR_EVENTS:
            # Return 200 for unsubscribed events — don't make Bitbucket retry
            log.debug("webhook.bitbucket.event_ignored", event_key=event_key)
            return Response(status_code=200)

        # Parse and enqueue
        payload = await request.json()
        pr_event = parse_pr_payload(payload)
        if pr_event is None:
            raise HTTPException(status_code=422, detail="Unrecognised payload shape")

        await queue.put(pr_event)
        log.info(
            "webhook.bitbucket.enqueued",
            repo=pr_event.repo_full_name,
            pr=pr_event.pr_id,
            event=event_key,
        )
        return Response(status_code=200)

    return app
