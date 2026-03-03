"""Brusky agent entrypoint — `python -m brusky` or `brusky` CLI."""

import asyncio
import sys

import structlog

log = structlog.get_logger()


async def _main() -> None:
    log.info("brusky.start", version="0.1.0")
    # Placeholder — agent phases will wire in here
    log.info("brusky.ready", message="Infrastructure layer ready. Awaiting phase implementation.")


def main() -> None:
    asyncio.run(_main())


if __name__ == "__main__":
    main()
