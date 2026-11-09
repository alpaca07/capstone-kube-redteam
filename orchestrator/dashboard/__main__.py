"""python -m orchestrator.dashboard 진입점."""
from __future__ import annotations

import sys
from pathlib import Path

# python -m orchestrator.dashboard 로 돌 때 레포 루트를 경로에.
_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from orchestrator.dashboard.server import main  # noqa: E402

if __name__ == "__main__":
    main()
