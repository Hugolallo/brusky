"""HTML report rendering: structure, escaping, self-containment, CLI wiring.

The HTML report is opened directly in a browser by non-technical users, so these
tests are deliberately paranoid about: it always being a complete, self-contained
document; every value being HTML-escaped (advisory text is untrusted); and it
rendering correctly across the empty case, every severity, and enriched findings.
"""

from __future__ import annotations

from html.parser import HTMLParser

import pytest

from brusky import htmlreport, report
from brusky.model import (
    Finding,
    FixGuidance,
    ResolvedDep,
    ScanResult,
    Severity,
    Vulnerability,
)

# ── builders ──────────────────────────────────────────────────────────────────


def _finding(
    name="lodash",
    version="4.17.4",
    vuln_id="GHSA-lodash-pp",
    summary="Prototype pollution in lodash",
    sev=Severity.CRITICAL,
    *,
    ecosystem="npm",
    fixed="4.17.21",
    status="NEW",
    direct=True,
    dev=False,
    reachable=None,
    cvss=None,
    guidance=None,
) -> Finding:
    dep = ResolvedDep(ecosystem, name, version, direct=direct, dev=dev)
    vuln = Vulnerability(
        id=vuln_id,
        summary=summary,
        severity=sev,
        fixed_version=fixed,
        cvss_score=cvss,
        references=[f"https://github.com/advisories/{vuln_id}"],
    )
    return Finding(dep=dep, vuln=vuln, status=status, reachable=reachable, guidance=guidance)


def _result(findings, **kw) -> ScanResult:
    kw.setdefault("target", "/repo/app")
    kw.setdefault("timestamp", "2026-07-06T09:00:00+00:00")
    kw.setdefault("scanned_deps", len(findings))
    kw.setdefault("ecosystems", ["npm"])
    return ScanResult(findings=list(findings), **kw)


class _WellFormed(HTMLParser):
    """Assert every non-void tag is properly closed and nesting is balanced."""

    VOID = {"meta", "br", "hr", "img", "input", "link", "source", "col", "area", "base"}

    def __init__(self) -> None:
        super().__init__()
        self.stack: list[str] = []
        self.errors: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):  # <tag/>
        pass

    def handle_endtag(self, tag):
        if tag in self.VOID:
            return
        if not self.stack:
            self.errors.append(f"closing </{tag}> with empty stack")
            return
        if self.stack[-1] != tag:
            # allow implicit closes only if the tag exists somewhere in the stack
            if tag in self.stack:
                self.errors.append(f"mismatched nesting near </{tag}>: stack={self.stack}")
            else:
                self.errors.append(f"stray </{tag}>")
            return
        self.stack.pop()


def _assert_well_formed(doc: str) -> None:
    p = _WellFormed()
    p.feed(doc)
    assert not p.errors, p.errors
    assert not p.stack, f"unclosed tags: {p.stack}"


# ── document shape ─────────────────────────────────────────────────────────────


def test_produces_complete_self_contained_document():
    html = htmlreport.to_html(_result([_finding()]))

    assert html.startswith("<!DOCTYPE html>")
    assert '<html lang="en">' in html
    assert html.rstrip().endswith("</html>")
    assert html.count("<body") == 1 and html.count("</body>") == 1
    # everything inlined — no external stylesheets or scripts to fetch
    assert "<link" not in html
    assert 'src="http' not in html and "src='http" not in html
    assert "cdn" not in html.lower()
    _assert_well_formed(html)


def test_reexported_through_report_module():
    assert report.to_html is htmlreport.to_html
    assert report.to_html(_result([_finding()])).startswith("<!DOCTYPE")


def test_empty_result_is_clean_bill_of_health():
    html = htmlreport.to_html(_result([], scanned_deps=42, ecosystems=["npm", "Packagist"]))

    assert "No known vulnerabilities" in html
    assert "Clean" in html
    assert "42" in html  # scanned dep count still shown
    # no findings section / filter chips when there's nothing to show
    assert 'id="findings"' not in html
    assert 'class="chip-row"' not in html
    _assert_well_formed(html)


# ── metrics & severity ─────────────────────────────────────────────────────────


def test_all_severities_render_with_labels_and_counts():
    findings = [
        _finding("a", vuln_id="V-CRIT", sev=Severity.CRITICAL),
        _finding("b", vuln_id="V-HIGH", sev=Severity.HIGH),
        _finding("c", vuln_id="V-MED", sev=Severity.MEDIUM),
        _finding("d", vuln_id="V-LOW", sev=Severity.LOW),
        _finding("e", vuln_id="V-UNK", sev=Severity.UNKNOWN, fixed=None),
    ]
    html = htmlreport.to_html(_result(findings))

    for label in ("Critical", "High", "Medium", "Low", "Unknown"):
        assert label in html
    # hero total
    assert ">5</div>" in html
    # severity is never color-only: each pill carries a text label
    assert html.count('<span class="sev-pill"') == 5
    _assert_well_formed(html)


def test_posture_escalates_to_worst_severity():
    high = htmlreport.to_html(_result([_finding(sev=Severity.HIGH)]))
    assert "High risk" in high

    crit = htmlreport.to_html(_result([_finding(sev=Severity.CRITICAL)]))
    assert "Critical exposure" in crit


def test_metrics_count_new_existing_fixable_reachable():
    findings = [
        _finding("a", vuln_id="V1", status="NEW", fixed="1.0.0", reachable=True),
        _finding("b", vuln_id="V2", status="EXISTING", fixed=None),
        _finding("c", vuln_id="V3", status="WORSENED", fixed="2.0.0"),
    ]
    html = htmlreport.to_html(_result(findings))

    assert "new / worsened" in html
    assert "already known" in html
    assert "have a fix available" in html
    assert "reachable in code" in html  # only appears because one is reachable


# ── escaping (untrusted advisory text) ──────────────────────────────────────────


def test_all_untrusted_text_is_escaped():
    evil = '<script>alert("xss")</script> & <img src=x onerror=1>'
    f = _finding(name="pkg", summary=evil, vuln_id="GHSA-<evil>")
    html = htmlreport.to_html(_result([f], target="/a<b>&c"))

    # the raw payload must never appear unescaped anywhere in the document
    assert "<script>alert" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html
    # target path with markup is escaped too
    assert "/a<b>" not in html
    assert "/a&lt;b&gt;" in html
    _assert_well_formed(html)


def test_advisory_url_is_linked():
    f = _finding()
    html = htmlreport.to_html(_result([f]))
    assert 'href="https://github.com/advisories/GHSA-lodash-pp"' in html
    assert 'rel="noopener noreferrer"' in html


def test_missing_summary_has_fallback_text():
    f = _finding(summary="")
    html = htmlreport.to_html(_result([f]))
    assert "No summary provided." in html


# ── tags, versions, cvss ─────────────────────────────────────────────────────


def test_dependency_tags_and_version_flow():
    transitive_dev = _finding(direct=False, dev=True, fixed="4.17.21")
    html = htmlreport.to_html(_result([transitive_dev]))
    assert "transitive" in html
    assert ">dev<" in html
    assert "4.17.4" in html and "4.17.21" in html  # installed → fix


def test_no_fix_available_is_shown():
    html = htmlreport.to_html(_result([_finding(fixed=None)]))
    assert "no fix yet" in html


def test_cvss_score_formats_cleanly():
    html = htmlreport.to_html(_result([_finding(cvss=9.8)]))
    assert "CVSS 9.8" in html
    html_int = htmlreport.to_html(_result([_finding(cvss=10.0)]))
    assert "CVSS 10" in html_int


# ── guidance (M3 explainer) ─────────────────────────────────────────────────────


def test_guidance_block_renders_every_field():
    g = FixGuidance(
        why_vulnerable="Prototype pollution via _.merge.",
        impact="Attacker alters Object.prototype.",
        severity_rationale="Network-exploitable, no auth.",
        upgrade_summary="Bump lodash to 4.17.21.",
        breaking_changes=["_.template signature changed"],
        code_touchpoints=[{"file": "index.js", "line": 12, "note": "uses _.merge"}],
        effort="trivial",
        confidence="high",
        sources=["https://example.com/rel"],
        model="fake-model",
    )
    html = htmlreport.to_html(_result([_finding(guidance=g)]))

    assert "AI explainer" in html
    assert "high confidence" in html
    assert "Prototype pollution via _.merge." in html
    assert "Attacker alters Object.prototype." in html
    assert "trivial effort" in html
    assert "_.template signature changed" in html
    assert "index.js" in html and ":12" in html
    assert 'href="https://example.com/rel"' in html
    assert "fake-model" in html
    _assert_well_formed(html)


def test_guidance_with_partial_fields_does_not_break():
    g = FixGuidance(why_vulnerable="Just this one field.", confidence="")
    html = htmlreport.to_html(_result([_finding(guidance=g)]))
    assert "Just this one field." in html
    assert "unrated confidence" in html
    _assert_well_formed(html)


def test_guidance_escapes_untrusted_llm_text():
    g = FixGuidance(why_vulnerable="<script>x</script>", model="<b>m</b>")
    html = htmlreport.to_html(_result([_finding(guidance=g)]))
    assert "<script>x</script>" not in html
    assert "&lt;script&gt;" in html


# ── errors ──────────────────────────────────────────────────────────────────


def test_errors_render_as_banner():
    res = _result([], errors=["No supported manifests found."])
    html = htmlreport.to_html(res)
    assert "banner-warn" in html
    assert "No supported manifests found." in html


# ── end-to-end over a real scan ─────────────────────────────────────────────────


def test_html_from_real_scan(npm_app, mock_osv, tmp_path):
    from brusky.scan import run_scan
    from brusky.state import State

    with State(tmp_path / "state.db") as st:
        result = run_scan(npm_app, enabled={"npm"}, state=st, osv=mock_osv)

    html = htmlreport.to_html(result)
    assert "lodash" in html
    assert "GHSA-lodash-pp" in html
    assert "Critical" in html
    _assert_well_formed(html)


# ── CLI wiring ───────────────────────────────────────────────────────────────


def test_cli_writes_html_file(tmp_path):
    """--html writes a file even on the no-lockfile path, without touching stdout."""
    from brusky.__main__ import main

    out = tmp_path / "report.html"
    code = main(
        ["scan", str(tmp_path), "--html", str(out), "--db", str(tmp_path / "s.db")]
    )
    assert code == 0
    assert out.exists()
    doc = out.read_text(encoding="utf-8")
    assert doc.startswith("<!DOCTYPE html>")
    _assert_well_formed(doc)


def test_cli_html_defaults_to_report_filename(tmp_path, monkeypatch):
    from brusky.__main__ import main

    monkeypatch.chdir(tmp_path)
    code = main(["scan", str(tmp_path), "--html", "--db", str(tmp_path / "s.db")])
    assert code == 0
    assert (tmp_path / "brusky-report.html").exists()


@pytest.mark.parametrize("bad", ["", "no json", None])
def test_fmt_score_and_helpers(bad):
    # guard the small formatting helpers against odd input
    assert htmlreport._fmt_score(7.5) == "7.5"
    assert htmlreport._fmt_score(8.0) == "8"
    assert htmlreport._pluralize(1, "dep", "deps") == "dep"
    assert htmlreport._pluralize(2, "dep", "deps") == "deps"
