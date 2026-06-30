"""Docker collector + EOL advisory + reachability tagging."""

from __future__ import annotations

from brusky.advisories import EOLClient
from brusky.collectors.docker import DockerCollector, _parse_image_ref
from brusky.model import ResolvedDep, Severity
from brusky.prioritize import assemble


def test_parse_image_ref():
    assert _parse_image_ref("node:16-alpine") == ("node", "16-alpine")
    assert _parse_image_ref("library/python:3.9") == ("python", "3.9")
    assert _parse_image_ref("myreg:5000/api/node") == ("node", "latest")
    assert _parse_image_ref("php@sha256:abc") == ("php", "(digest)")
    assert _parse_image_ref("redis") == ("redis", "latest")


def test_collector_skips_stage_refs_and_keeps_real_images(docker_app):
    deps = {d.name: d for d in DockerCollector().collect(docker_app)}

    # node (build base) and nginx (final base) are real; "build"/"test" stages aren't.
    assert set(deps) == {"node", "nginx"}
    assert "build" not in deps and "test" not in deps
    assert deps["node"].version == "16-alpine"
    assert deps["node"].ecosystem == "Docker"
    assert deps["node"].direct is True
    assert deps["nginx"].version == "latest"


def test_eol_flags_old_cycle_and_unpinned(mock_eol):
    node16 = ResolvedDep("Docker", "node", "16-alpine", direct=True)
    nginx = ResolvedDep("Docker", "nginx", "latest", direct=True)

    result = mock_eol.check([node16, nginx])

    node_vuln = result[node16.coordinate][0]
    assert node_vuln.id == "EOL-node-16"
    assert node_vuln.severity is Severity.HIGH
    assert node_vuln.fixed_version == "20"      # newest still-supported cycle

    nginx_vuln = result[nginx.coordinate][0]
    assert nginx_vuln.id == "UNPINNED-nginx"
    assert nginx_vuln.severity is Severity.MEDIUM


def test_supported_cycle_and_digest_produce_no_finding(mock_eol):
    supported = ResolvedDep("Docker", "node", "20", direct=True)
    pinned = ResolvedDep("Docker", "node", "(digest)", direct=True)
    unknown = ResolvedDep("Docker", "some-internal-image", "1.0", direct=True)

    assert mock_eol.check([supported, pinned, unknown]) == {}


def test_reachability_deprioritizes_dev_deps():
    runtime = ResolvedDep("npm", "lodash", "4.17.4", dev=False)
    dev = ResolvedDep("npm", "mocha", "5.2.0", dev=True)
    from brusky.model import Vulnerability

    vmap = {
        runtime.coordinate: [Vulnerability(id="A", severity=Severity.HIGH)],
        dev.coordinate: [Vulnerability(id="B", severity=Severity.HIGH)],
    }
    findings = {f.dep.name: f for f in assemble([runtime, dev], vmap)}
    assert findings["lodash"].reachable is True
    assert findings["mocha"].reachable is False


def test_eol_client_is_context_manager():
    with EOLClient(today="2026-06-30") as client:
        assert client._today == "2026-06-30"
