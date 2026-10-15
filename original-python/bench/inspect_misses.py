"""Print fixer failures and the code of selected benchmark misses (debugging aid)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
label = sys.argv[1] if len(sys.argv) > 1 else "v2"
ids = sys.argv[2:]

report = json.loads((ROOT / "bench" / "results" / f"{label}.json").read_text(encoding="utf-8"))
for f in report["fix_failures"][:12]:
    print("FIX", f["file"], "->", f["error"])

rows = {}
for line in (ROOT / "bench" / "data" / "SecurityEval-main" / "dataset.jsonl").read_text(encoding="utf-8").splitlines():
    if line.strip():
        r = json.loads(line)
        rows[r["ID"]] = r["Insecure_code"]

for key in ids:
    code = rows.get(key)
    if code is None:
        path = ROOT / "bench" / "data" / "bandit-main" / "examples" / key
        code = path.read_text(encoding="utf-8", errors="replace") if path.exists() else "(not found)"
    kept = [ln for ln in code.splitlines() if ln.strip() and not ln.strip().startswith(("'''", '"""', "#"))]
    print("=====", key)
    print("\n".join(kept[:28]))
