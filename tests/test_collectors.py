"""Collectors must read resolved versions from lockfiles, incl. transitive + dev."""

from __future__ import annotations

from brusky.collectors.composer import ComposerCollector
from brusky.collectors.npm import NpmCollector


def test_npm_collects_direct_transitive_and_dev(npm_app):
    deps = {d.name: d for d in NpmCollector().collect(npm_app)}

    assert deps["lodash"].version == "4.17.4"
    assert deps["lodash"].direct is True
    assert deps["lodash"].dev is False
    assert deps["lodash"].ecosystem == "npm"

    # mocha is a declared dev dependency
    assert deps["mocha"].dev is True
    assert deps["mocha"].direct is True

    # minimist is transitive (not in package.json) and dev-flagged in the lock
    assert deps["minimist"].direct is False
    assert deps["minimist"].dev is True


def test_composer_collects_and_normalizes_versions(composer_app):
    deps = {d.name: d for d in ComposerCollector().collect(composer_app)}

    assert deps["guzzlehttp/guzzle"].version == "6.5.0"
    assert deps["guzzlehttp/guzzle"].direct is True
    assert deps["guzzlehttp/guzzle"].ecosystem == "Packagist"

    # leading "v" stripped for OSV matching
    assert deps["psr/http-message"].version == "1.0.1"
    assert deps["psr/http-message"].direct is False  # transitive

    assert deps["phpunit/phpunit"].dev is True


def test_detect(npm_app, composer_app, tmp_path):
    assert NpmCollector().detect(npm_app) is True
    assert NpmCollector().detect(composer_app) is False
    assert ComposerCollector().detect(composer_app) is True
    assert ComposerCollector().detect(tmp_path) is False
