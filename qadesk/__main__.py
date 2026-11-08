from __future__ import annotations

import argparse
import sys

from .core import APP_VERSION, MODULE_IDS
from .ui.app import QADesktopApp


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="qa-desktop", description="QA Desktop suite")
    parser.add_argument("--module", choices=("suite",) + MODULE_IDS, default="suite",
                        help="open a single module instead of the full suite")
    parser.add_argument("--version", action="version",
                        version=f"qa-desktop {APP_VERSION}")
    args, _ = parser.parse_known_args(argv)
    app = QADesktopApp(module_id=args.module)
    return app.run([sys.argv[0]])


if __name__ == "__main__":
    raise SystemExit(main())
