import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for directory in ('common', 'amf-sniffer', 'smf-sniffer', 'ue-mapper', 'user-plane-path', '.github'):
    sys.path.insert(0, str(ROOT / directory))
