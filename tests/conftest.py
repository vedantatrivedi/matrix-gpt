import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORCHESTRATOR = ROOT / "orchestrator"
AGENTS_DIR = ORCHESTRATOR / "agents"
SAMPLE_APP_DIR = ROOT / "sample-app"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(AGENTS_DIR) not in sys.path:
    sys.path.insert(0, str(AGENTS_DIR))
if str(SAMPLE_APP_DIR) not in sys.path:
    sys.path.insert(0, str(SAMPLE_APP_DIR))
