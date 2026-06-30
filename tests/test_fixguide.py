"""M3: call-site grep, advisor parsing, enrichment + caching, report rendering."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

import brusky.fixguide.runner as enrich_mod
from brusky import report
from brusky.fixguide import select_findings
from brusky.fixguide.advisor import generate_guidance
from brusky.fixguide.callsites import find_callsites
from brusky.model import Finding, ResolvedDep, ScanResult, Severity, Vulnerability
from brusky.state import State

# ── a fake LLM provider ──────────────────────────────────────────────────────


@dataclass
class _Resp:
    content: str
    model: str = "fake-model"


class FakeLLM:
    """Records calls and returns a canned JSON guidance payload."""

    def __init__(self, content: str) -> None:
        self.content = content
        self.calls = 0

    async def complete(self, messages, *, system=None, **kw):
        self.calls += 1
        return _Resp(self.content)


_GOOD_JSON = """Here you go:
{
  "why_vulnerable": "Prototype pollution via _.merge.",
  "impact": "Attacker can alter Object.prototype.",
  "severity_rationale": "Network-exploitable, no auth.",
  "upgrade_summary": "Bump lodash to 4.17.21.",
  "breaking_changes": ["_.template signature changed"],
  "code_touchpoints": [
    {"file": "index.js", "line": 1, "note": "uses _.merge"},
    {"file": "ghost.js", "line": 99, "note": "not a real call site"}
  ],
  "effort": "trivial",
  "confidence": "high"
}"""


def _finding(status="NEW", sev=Severity.CRITICAL, dev=False, direct=True) -> Finding:
    dep = ResolvedDep("npm", "lodash", "4.17.4", direct=direct, dev=dev)
    vuln = Vulnerability(id="GHSA-x", summary="prototype pollution",
                         severity=sev, fixed_version="4.17.21",
                         references=["https://github.com/advisories/GHSA-x"])
    return Finding(dep=dep, vuln=vuln, status=status)


# ── call sites ───────────────────────────────────────────────────────────────


def test_find_callsites_npm(tmp_path):
    (tmp_path / "index.js").write_text("const _ = require('lodash')\nconsole.log(_)\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text("require('lodash')\n")  # excluded

    hits = find_callsites("npm", "lodash", tmp_path)
    assert len(hits) == 1
    assert hits[0]["file"] == "index.js"
    assert hits[0]["line"] == 1


def test_find_callsites_docker_is_empty(tmp_path):
    assert find_callsites("Docker", "node", tmp_path) == []


# ── advisor parsing ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_advisor_parses_and_validates_touchpoints():
    llm = FakeLLM(_GOOD_JSON)
    callsites = [{"file": "index.js", "line": 1, "text": "require('lodash')"}]

    g = await generate_guidance(
        _finding(), changelog_text="changelog", changelog_sources=["https://rel"],
        callsites=callsites, llm=llm,
    )

    assert g is not None
    assert g.why_vulnerable.startswith("Prototype pollution")
    assert g.confidence == "high"
    # the hallucinated ghost.js touchpoint is dropped; only the real one survives
    assert len(g.code_touchpoints) == 1
    assert g.code_touchpoints[0]["file"] == "index.js"
    # advisory_url + changelog source merged
    assert "https://rel" in g.sources
    assert any("GHSA-x" in s for s in g.sources)


@pytest.mark.asyncio
async def test_advisor_returns_none_on_unparseable_output():
    g = await generate_guidance(
        _finding(), changelog_text="", changelog_sources=[], callsites=[],
        llm=FakeLLM("no json here"),
    )
    assert g is None


# ── selection ────────────────────────────────────────────────────────────────


def test_select_findings_scopes():
    new_crit = _finding("NEW", Severity.CRITICAL)
    new_low = _finding("NEW", Severity.LOW)
    old_high = _finding("EXISTING", Severity.HIGH)
    result = ScanResult(target="/r", findings=[new_crit, new_low, old_high])

    assert select_findings(result, "none", 0) == []
    assert len(select_findings(result, "all", 0)) == 3
    auto = select_findings(result, "auto", 0)
    assert auto == [new_crit]                       # new + high/critical only
    assert len(select_findings(result, "all", 2)) == 2  # top-N cap


# ── enrichment + caching ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_enrich_sets_guidance_and_caches(tmp_path, monkeypatch):
    (tmp_path / "index.js").write_text("const _ = require('lodash')\n")

    async def fake_changelog(*a, **k):
        return "## 4.17.21\nfixes prototype pollution", ["https://rel/4.17.21"]

    monkeypatch.setattr(enrich_mod, "fetch_changelog", fake_changelog)
    llm = FakeLLM(_GOOD_JSON)

    with State(tmp_path / "state.db") as st:
        result = ScanResult(target=str(tmp_path), findings=[_finding()])
        n = await enrich_mod.enrich(result, tmp_path, state=st, llm=llm)
        assert n == 1
        assert result.findings[0].guidance is not None
        assert llm.calls == 1

        # second run with a fresh finding (same key/versions) hits the cache
        result2 = ScanResult(target=str(tmp_path), findings=[_finding()])
        n2 = await enrich_mod.enrich(result2, tmp_path, state=st, llm=llm)
        assert n2 == 0                       # reused, not regenerated
        assert llm.calls == 1                # no new LLM call
        assert result2.findings[0].guidance is not None


# ── report rendering ─────────────────────────────────────────────────────────


def test_report_renders_explainer_block():
    f = _finding()
    from brusky.model import FixGuidance
    f.guidance = FixGuidance(
        why_vulnerable="Prototype pollution.", impact="Bad.",
        upgrade_summary="Bump to 4.17.21.", confidence="high",
        code_touchpoints=[{"file": "index.js", "line": 1, "note": "uses _.merge"}],
        sources=["https://rel"], model="fake-model",
    )
    result = ScanResult(target="/r", findings=[f], scanned_deps=1, ecosystems=["npm"])

    md = report.to_markdown(result)
    assert "Explainers & upgrade guidance" in md
    assert "Why it's vulnerable" in md
    assert "index.js:1" in md
    assert "<details>" in md

    js = report.to_json(result)
    assert '"guidance"' in js
    assert '"confidence": "high"' in js
