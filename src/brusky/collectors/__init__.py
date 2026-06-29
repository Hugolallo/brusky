"""Ecosystem collectors (drivers). Importing this package registers them."""

from __future__ import annotations

from brusky.collectors import composer, npm  # noqa: F401  (side-effect: register)
from brusky.collectors.base import active_collectors, all_collectors, register

__all__ = ["active_collectors", "all_collectors", "register"]
