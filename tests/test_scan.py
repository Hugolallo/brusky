"""End-to-end scan over fixtures with a mocked OSV and a temp state DB."""

from __future__ import annotations

from brusky import report
from brusky.scan import run_scan
from brusky.state import State


def test_scan_npm_finds_lodash_as_new(npm_app, mock_osv, tmp_path):
    with State(tmp_path / "state.db") as st:
        result = run_scan(npm_app, enabled={"npm"}, state=st, osv=mock_osv)

    assert result.ecosystems == ["npm"]
    assert result.scanned_deps == 3  # lodash + mocha + minimist
    keys = {f.key for f in result.findings}
    assert "npm:lodash:GHSA-lodash-pp" in keys
    assert all(f.status == "NEW" for f in result.findings)


def test_second_scan_reports_no_new(npm_app, mock_osv, tmp_path):
    db = tmp_path / "state.db"
    with State(db) as st:
        run_scan(npm_app, enabled={"npm"}, state=st, osv=mock_osv)
    with State(db) as st:
        second = run_scan(npm_app, enabled={"npm"}, state=st, osv=mock_osv)

    assert second.new_findings == []
    assert all(f.status == "EXISTING" for f in second.findings)


def test_scan_docker_eol_and_unpinned(docker_app, mock_osv, mock_eol, tmp_path):
    with State(tmp_path / "state.db") as st:
        result = run_scan(
            docker_app, enabled={"docker"}, state=st, osv=mock_osv, eol=mock_eol
        )

    assert result.ecosystems == ["docker"]
    keys = {f.key for f in result.findings}
    assert "Docker:node:EOL-node-16" in keys      # EOL base image
    assert "Docker:nginx:UNPINNED-nginx" in keys  # floating tag
    # EOL (HIGH) ranks above UNPINNED (MEDIUM)
    assert result.ranked()[0].vuln.id == "EOL-node-16"


def test_no_lockfile_reports_error(tmp_path, mock_osv):
    with State(tmp_path / "state.db") as st:
        result = run_scan(tmp_path, state=st, osv=mock_osv)
    assert result.errors
    assert result.findings == []


def test_report_outputs(npm_app, mock_osv, tmp_path):
    with State(tmp_path / "state.db") as st:
        result = run_scan(npm_app, enabled={"npm"}, state=st, osv=mock_osv)

    md = report.to_markdown(result)
    assert "lodash" in md
    assert "Critical" in md
    assert "GHSA-lodash-pp" in md

    js = report.to_json(result)
    assert '"fixed_version": "4.17.12"' in js
