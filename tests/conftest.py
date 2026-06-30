"""Shared fixtures: a mocked OSV transport so tests never hit the network."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from brusky.advisories import EOLClient, OSVClient

FIXTURES = Path(__file__).parent / "fixtures"
TODAY = "2026-06-30"

# Canned OSV vuln details keyed by id. Only lodash@4.17.4 and guzzle@6.5.0 are
# "vulnerable"; everything else queries clean.
_VULN_DETAILS = {
    "GHSA-lodash-pp": {
        "id": "GHSA-lodash-pp",
        "summary": "Prototype pollution in lodash",
        "aliases": ["CVE-2019-10744"],
        "database_specific": {"severity": "CRITICAL"},
        "references": [{"url": "https://github.com/advisories/GHSA-lodash-pp"}],
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.12"}]}
                ],
            }
        ],
    },
    "GHSA-guzzle-x": {
        "id": "GHSA-guzzle-x",
        "summary": "Cookie header cross-domain leak in Guzzle",
        "aliases": ["CVE-2022-31042"],
        "severity": [{"type": "CVSS_V3", "score": "7.5"}],
        "references": [{"url": "https://github.com/advisories/GHSA-guzzle-x"}],
        "affected": [
            {
                "package": {"ecosystem": "Packagist", "name": "guzzlehttp/guzzle"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "6.5.6"}]}
                ],
            }
        ],
    },
}

# (ecosystem, name, version) -> list of vuln ids
_MATCHES = {
    ("npm", "lodash", "4.17.4"): ["GHSA-lodash-pp"],
    ("Packagist", "guzzlehttp/guzzle", "6.5.0"): ["GHSA-guzzle-x"],
}


def _handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/v1/querybatch":
        queries = json.loads(request.content)["queries"]
        results = []
        for q in queries:
            key = (q["package"]["ecosystem"], q["package"]["name"], q["version"])
            ids = _MATCHES.get(key, [])
            results.append({"vulns": [{"id": i} for i in ids]})
        return httpx.Response(200, json={"results": results})

    if request.url.path.startswith("/v1/vulns/"):
        vuln_id = request.url.path.rsplit("/", 1)[-1]
        detail = _VULN_DETAILS.get(vuln_id)
        if detail is None:
            return httpx.Response(404)
        return httpx.Response(200, json=detail)

    return httpx.Response(404)


@pytest.fixture
def mock_osv() -> OSVClient:
    transport = httpx.MockTransport(_handler)
    client = httpx.Client(base_url="https://api.osv.dev", transport=transport)
    return OSVClient(client=client)


@pytest.fixture
def npm_app() -> Path:
    return FIXTURES / "npm-app"


@pytest.fixture
def composer_app() -> Path:
    return FIXTURES / "composer-app"


@pytest.fixture
def docker_app() -> Path:
    return FIXTURES / "docker-app"


# endoflife.date mock — node 16 is EOL, 20 is supported.
# Keyed by endoflife slug ("node" image resolves to the "nodejs" product).
_EOL_PRODUCTS = {
    "nodejs": [
        {"cycle": "20", "eol": "2027-04-30"},
        {"cycle": "18", "eol": "2025-04-30"},
        {"cycle": "16", "eol": "2023-09-11"},
    ],
}


def _eol_handler(request: httpx.Request) -> httpx.Response:
    product = request.url.path.removeprefix("/api/").removesuffix(".json")
    cycles = _EOL_PRODUCTS.get(product)
    if cycles is None:
        return httpx.Response(404)
    return httpx.Response(200, json=cycles)


@pytest.fixture
def mock_eol() -> EOLClient:
    transport = httpx.MockTransport(_eol_handler)
    client = httpx.Client(base_url="https://endoflife.date", transport=transport)
    return EOLClient(client=client, today=TODAY)
