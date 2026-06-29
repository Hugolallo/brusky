"""State diffing: NEW on first sight, EXISTING after, WORSENED on severity rise."""

from __future__ import annotations

from brusky.model import Finding, ResolvedDep, Severity, Vulnerability
from brusky.state import State


def _finding(sev: Severity) -> Finding:
    dep = ResolvedDep("npm", "lodash", "4.17.4", direct=True)
    vuln = Vulnerability(id="GHSA-lodash-pp", severity=sev)
    return Finding(dep=dep, vuln=vuln)


def test_new_then_existing(tmp_path):
    db = tmp_path / "state.db"
    target = "/repo"

    with State(db) as st:
        f = _finding(Severity.HIGH)
        st.classify(target, [f], "2026-01-01T00:00:00")
        assert f.status == "NEW"
        assert f.first_seen == "2026-01-01T00:00:00"
        st.record(target, [f], "2026-01-01T00:00:00")

    with State(db) as st:
        f = _finding(Severity.HIGH)
        st.classify(target, [f], "2026-01-02T00:00:00")
        assert f.status == "EXISTING"
        assert f.first_seen == "2026-01-01T00:00:00"  # preserved from first sight


def test_worsened_on_severity_increase(tmp_path):
    db = tmp_path / "state.db"
    target = "/repo"

    with State(db) as st:
        f = _finding(Severity.MEDIUM)
        st.classify(target, [f], "2026-01-01T00:00:00")
        st.record(target, [f], "2026-01-01T00:00:00")

    with State(db) as st:
        f = _finding(Severity.CRITICAL)
        st.classify(target, [f], "2026-01-02T00:00:00")
        assert f.status == "WORSENED"
        assert f.first_seen == "2026-01-01T00:00:00"
