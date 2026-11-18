"""Shared fixture: generate the dataset once in a temp folder."""
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

_cache: dict = {}


def data_dir() -> Path:
    if "dir" not in _cache:
        tmp = tempfile.mkdtemp(prefix="soc-lab-")
        subprocess.run([sys.executable, str(ROOT / "src" / "generate_logs.py"), "--users", "300",
                        "--seed", "42", "--start", "2026-10-01", "--out", tmp],
                       check=True, capture_output=True)
        _cache["dir"] = Path(tmp)
    return _cache["dir"]


def logs_and_rules():
    from engine import load_logs, load_rules
    if "logs" not in _cache:
        _cache["logs"] = load_logs(data_dir())
        _cache["rules"] = load_rules(ROOT / "rules")
    return _cache["logs"], _cache["rules"]
