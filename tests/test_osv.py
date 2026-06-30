"""OSV client: batch match, detail parse, severity + fixed-version resolution."""

from __future__ import annotations

from brusky.model import ResolvedDep, Severity


def test_finds_vuln_with_severity_and_fix(mock_osv):
    lodash = ResolvedDep("npm", "lodash", "4.17.4", direct=True)
    clean = ResolvedDep("npm", "express", "4.18.2", direct=True)

    result = mock_osv.find_vulnerabilities([lodash, clean])

    assert clean.coordinate not in result
    vulns = result[lodash.coordinate]
    assert len(vulns) == 1
    v = vulns[0]
    assert v.id == "GHSA-lodash-pp"
    assert v.severity is Severity.CRITICAL
    assert v.fixed_version == "4.17.12"
    assert "CVE-2019-10744" in v.aliases
    assert v.advisory_url.endswith("GHSA-lodash-pp")


def test_numeric_cvss_score_buckets_to_high(mock_osv):
    guzzle = ResolvedDep("Packagist", "guzzlehttp/guzzle", "6.5.0", direct=True)
    result = mock_osv.find_vulnerabilities([guzzle])
    v = result[guzzle.coordinate][0]
    assert v.severity is Severity.HIGH
    assert v.cvss_score == 7.5
    assert v.fixed_version == "6.5.6"


def test_clean_deps_return_empty(mock_osv):
    deps = [ResolvedDep("npm", "left-pad", "1.3.0")]
    assert mock_osv.find_vulnerabilities(deps) == {}


def test_cvss_vector_scoring():
    from brusky.advisories.osv import _cvss_base_score

    # Known reference vectors from the CVSS v3.1 spec examples.
    assert _cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert _cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H") == 7.2
    assert _cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L") == 5.3
    assert _cvss_base_score("not-a-vector") is None


def test_moderate_label_maps_to_medium():
    from brusky.model import Severity

    assert Severity.parse("MODERATE") is Severity.MEDIUM
