"""Dev wrapper around ``wifit3.wireless_capabilities``; the module is the product tool.

    uv run python scripts/capability_probe.py [--json]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from wifit3.wireless_capabilities import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
