"""Advisory drivers — sources of vulnerability truth.

OSV.dev covers package ecosystems (npm, Packagist, …); endoflife.date covers
Docker base-image freshness, which OSV does not track.
"""

from __future__ import annotations

from brusky.advisories.eol import EOLClient
from brusky.advisories.osv import OSVClient

__all__ = ["EOLClient", "OSVClient"]
