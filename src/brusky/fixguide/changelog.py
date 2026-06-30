"""Fetch real upstream release notes for the upgrade window.

Resolves a package's source repository (npm registry / Packagist), then pulls
its GitHub Releases and keeps the entries between the installed and fixed
versions. This is the *factual* basis for the advisor's "breaking changes" — the
model is only allowed to cite what appears here. Everything soft-fails to an
empty changelog, which the advisor reports as lower confidence.
"""

from __future__ import annotations

import re

import httpx
import structlog

log = structlog.get_logger()

_GITHUB_RE = re.compile(r"github\.com[:/]+([^/]+)/([^/.]+)")
_MAX_CHARS = 6000


async def fetch_changelog(
    ecosystem: str,
    name: str,
    installed: str,
    fixed: str | None,
    *,
    client: httpx.AsyncClient,
    token: str = "",
) -> tuple[str, list[str]]:
    """Return (changelog_text, source_urls). Empty text if nothing was found."""
    repo = await _github_repo(ecosystem, name, client)
    if not repo:
        return "", []
    owner, name_ = repo
    releases = await _releases(owner, name_, client, token)
    if not releases:
        return "", [f"https://github.com/{owner}/{name_}"]

    relevant = [r for r in releases if _in_range(r.get("tag_name", ""), installed, fixed)]
    chosen = relevant or _fallback(releases, fixed)

    chunks, sources = [], []
    for r in chosen:
        title = r.get("name") or r.get("tag_name", "")
        body = (r.get("body") or "").strip()
        chunks.append(f"## {title}\n{body}")
        if url := r.get("html_url"):
            sources.append(url)
    text = "\n\n".join(chunks)[:_MAX_CHARS]
    return text, sources


# ── repository resolution ────────────────────────────────────────────────────


async def _github_repo(
    ecosystem: str, name: str, client: httpx.AsyncClient
) -> tuple[str, str] | None:
    if ecosystem == "npm":
        url = await _npm_repo_url(name, client)
    elif ecosystem == "Packagist":
        url = await _packagist_repo_url(name, client)
    else:
        return None
    if not url:
        return None
    m = _GITHUB_RE.search(url)
    return (m.group(1), m.group(2)) if m else None


async def _npm_repo_url(name: str, client: httpx.AsyncClient) -> str | None:
    data = await _get_json(client, f"https://registry.npmjs.org/{name}")
    if not data:
        return None
    repo = data.get("repository")
    if isinstance(repo, dict):
        return repo.get("url")
    return repo if isinstance(repo, str) else None


async def _packagist_repo_url(name: str, client: httpx.AsyncClient) -> str | None:
    data = await _get_json(client, f"https://packagist.org/packages/{name}.json")
    if not data:
        return None
    return data.get("package", {}).get("repository")


async def _releases(owner: str, repo: str, client: httpx.AsyncClient, token: str) -> list[dict]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    data = await _get_json(
        client,
        f"https://api.github.com/repos/{owner}/{repo}/releases?per_page=100",
        headers=headers,
    )
    return data if isinstance(data, list) else []


# ── helpers ──────────────────────────────────────────────────────────────────


async def _get_json(client: httpx.AsyncClient, url: str, *, headers: dict | None = None):
    try:
        resp = await client.get(url, headers=headers or {}, follow_redirects=True)
        resp.raise_for_status()
        return resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        log.debug("changelog.fetch_failed", url=url, error=str(exc))
        return None


def _fallback(releases: list[dict], fixed: str | None) -> list[dict]:
    """When range-matching finds nothing, show the latest few releases — but never
    any *newer* than the fix, so we don't mislead with post-fix changes."""
    if fixed:
        capped = [r for r in releases if _vkey(r.get("tag_name", "")) <= _vkey(fixed)]
        return capped[:3]
    return releases[:3]


def _vkey(version: str) -> tuple[int, ...]:
    nums = re.findall(r"\d+", version)
    return tuple(int(n) for n in nums[:4]) if nums else (0,)


def _in_range(tag: str, installed: str, fixed: str | None) -> bool:
    v = _vkey(tag)
    if v <= _vkey(installed):
        return False
    return v <= _vkey(fixed) if fixed else True
