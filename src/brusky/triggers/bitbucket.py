"""Bitbucket Cloud webhook verification and API client."""

from __future__ import annotations

import hashlib
import hmac
import logging

import httpx

from brusky.triggers.models import ChangedFile, PREvent

log = logging.getLogger(__name__)

_BB_API = "https://api.bitbucket.org/2.0"

# Events we care about
PR_EVENTS = {"pullrequest:created", "pullrequest:updated"}


def verify_signature(secret: str, body: bytes, sig_header: str) -> bool:
    """Verify X-Hub-Signature header (sha256=<hex>) against request body."""
    if not secret:
        # No secret configured — skip verification (not recommended for production)
        return True
    if not sig_header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    received = sig_header.removeprefix("sha256=")
    return hmac.compare_digest(expected, received)


def parse_pr_payload(payload: dict) -> PREvent | None:
    """Extract a PREvent from a Bitbucket webhook payload dict. Returns None if unrecognised."""
    try:
        pr = payload["pullrequest"]
        repo = payload["repository"]
        return PREvent(
            repo_full_name=repo["full_name"],
            pr_id=pr["id"],
            pr_title=pr["title"],
            source_commit=pr["source"]["commit"]["hash"],
            source_branch=pr["source"]["branch"]["name"],
            destination_branch=pr["destination"]["branch"]["name"],
            pr_url=pr["links"]["html"]["href"],
        )
    except (KeyError, TypeError) as exc:
        log.warning("bitbucket.parse_pr_payload.failed", error=str(exc))
        return None


class BitbucketClient:
    """Async HTTP client for the Bitbucket Cloud REST API v2."""

    def __init__(self, access_token: str) -> None:
        self._client = httpx.AsyncClient(
            base_url=_BB_API,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=30.0,
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def get_changed_files(self, repo: str, pr_id: int) -> list[ChangedFile]:
        """Return list of changed files in a PR via the diffstat endpoint.

        Handles pagination — Bitbucket returns up to 500 entries per page.
        """
        files: list[ChangedFile] = []
        url = f"/repositories/{repo}/pullrequests/{pr_id}/diffstat"
        while url:
            resp = await self._client.get(url)
            resp.raise_for_status()
            data = resp.json()
            for entry in data.get("values", []):
                # Each entry has "new" (file after change) and "status"
                new_file = entry.get("new") or entry.get("old")
                if new_file and new_file.get("path"):
                    files.append(ChangedFile(
                        path=new_file["path"],
                        status=entry.get("status", "modified"),
                    ))
            # Follow pagination
            next_page = data.get("next")
            url = next_page.removeprefix(_BB_API) if next_page else ""
        return files

    async def get_file_content(self, repo: str, commit: str, path: str) -> str:
        """Fetch raw file content at a specific commit."""
        resp = await self._client.get(f"/repositories/{repo}/src/{commit}/{path}")
        if resp.status_code == 404:
            return ""  # deleted file
        resp.raise_for_status()
        return resp.text

    async def enrich_pr_event(self, event: PREvent) -> PREvent:
        """Fetch changed files + their content and attach to the event."""
        files = await self.get_changed_files(event.repo_full_name, event.pr_id)
        enriched: list[ChangedFile] = []
        for f in files:
            if f.status == "removed":
                enriched.append(f)
                continue
            content = await self.get_file_content(
                event.repo_full_name, event.source_commit, f.path
            )
            enriched.append(ChangedFile(path=f.path, status=f.status, content=content))
        event.changed_files = enriched
        return event
