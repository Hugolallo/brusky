"""Brusky agent entrypoint — `python -m brusky` or `brusky` CLI."""

import uvicorn

from brusky.triggers.server import build_app


def main() -> None:
    app = build_app()
    uvicorn.run(app, host="0.0.0.0", port=8080, log_config=None)


if __name__ == "__main__":
    main()
