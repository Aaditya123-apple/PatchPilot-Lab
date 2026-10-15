"""Benchmark the static engine and rule-based fixer against public datasets.

Datasets (download with bench/fetch_datasets.ps1 or by hand into bench/data/):
  * SecurityEval  (s2e-lab/SecurityEval, dataset.jsonl): 121 vulnerable Python samples labelled with CWE IDs.
  * Bandit examples (PyCQA/bandit, examples/ + tests/functional/test_functional.py): example files with the
    number of MEDIUM/HIGH issues Bandit's own tests expect.
  * Benign corpus: the Python standard library (tests excluded) to measure false alarms, speed and crashes.

Usage: python -m bench.evaluate [--label NAME] [--stdlib PATH]
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
import time
import traceback
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.agent import public_names  # noqa: E402
from src.diffing import apply_unified_diff, unified_diff  # noqa: E402
from src.fixers import apply_rule_fixes  # noqa: E402
from src.models import Severity, SourceFile  # noqa: E402
from src.scanner import compare_findings, static_scan  # noqa: E402

DATA = ROOT / "bench" / "data"
RESULTS = ROOT / "bench" / "results"

# CWEs that describe the same weakness family; a finding in the family counts as a CWE match.
FAMILIES = [
    {"CWE-259", "CWE-321", "CWE-798", "CWE-522"},
    {"CWE-327", "CWE-328", "CWE-916", "CWE-759", "CWE-760", "CWE-326", "CWE-329"},
    {"CWE-330", "CWE-331", "CWE-338", "CWE-339"},
    {"CWE-94", "CWE-95"},
    {"CWE-78", "CWE-77"},
    {"CWE-502"},
    {"CWE-611", "CWE-776", "CWE-827"},
    {"CWE-295", "CWE-297"},
    {"CWE-22", "CWE-23", "CWE-36", "CWE-73", "CWE-99"},
    {"CWE-79", "CWE-80"},
    {"CWE-329", "CWE-1204"},
    {"CWE-522", "CWE-916", "CWE-256"},
    {"CWE-319", "CWE-614", "CWE-311"},
    {"CWE-400", "CWE-730", "CWE-1333"},
    {"CWE-377", "CWE-379"},
    {"CWE-215", "CWE-489", "CWE-209"},
]


def norm_cwe(cwe: str | None) -> str | None:
    if not cwe:
        return None
    return "CWE-" + str(int(cwe.split("-")[1]))


def cwe_match(label: str, found: set[str]) -> bool:
    label = norm_cwe(label)
    if label in found:
        return True
    return any(label in fam and fam & found for fam in FAMILIES)


def material(findings: list) -> list:
    """Findings at Medium severity or above (Bandit's MEDIUM/HIGH equivalent)."""
    return [f for f in findings if f.severity.rank >= Severity.MEDIUM.rank]


# ---------------------------------------------------------------- loaders

def load_securityeval() -> list[tuple[str, str, str]]:
    path = DATA / "SecurityEval-main" / "dataset.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [(r["ID"], r["ID"].split("_")[0], r["Insecure_code"]) for r in rows]


def load_bandit() -> list[tuple[str, int, str]]:
    base = DATA / "bandit-main"
    tree = ast.parse((base / "tests" / "functional" / "test_functional.py").read_text(encoding="utf-8"))
    out: list[tuple[str, int, str]] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef):
            continue
        expect = None
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "expect" for t in node.targets):
                try:
                    expect = ast.literal_eval(node.value)
                except ValueError:
                    expect = None
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "check_example"
                    and node.args and isinstance(node.args[0], ast.Constant) and isinstance(expect, dict)
                    and "SEVERITY" in expect):
                name = node.args[0].value
                sev = expect["SEVERITY"]
                count = int(sev.get("MEDIUM", 0)) + int(sev.get("HIGH", 0))
                file = base / "examples" / name
                if file.exists() and file.suffix == ".py":
                    out.append((name, count, file.read_text(encoding="utf-8", errors="replace")))
    return out


def load_stdlib(path: Path, limit: int | None = None) -> list[tuple[str, str]]:
    skip = ("test", "tests", "idle_test", "site-packages", "__pycache__")
    out = []
    for f in sorted(path.rglob("*.py")):
        if any(part in skip or part.startswith("test_") for part in f.relative_to(path).parts):
            continue
        try:
            out.append((f.relative_to(path).as_posix(), f.read_text(encoding="utf-8")))
        except (UnicodeDecodeError, OSError):
            continue
        if limit and len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------- fixer pressure test

def check_fix(name: str, code: str, findings: list, stats: Counter, failures: list) -> None:
    try:
        fix = apply_rule_fixes(code, findings)
    except Exception as exc:  # noqa: BLE001
        stats["fix_crash"] += 1
        failures.append({"file": name, "error": f"fixer crash: {exc!r}", "trace": traceback.format_exc()[-800:]})
        return
    if not fix.addressed:
        return
    stats["fix_files"] += 1
    stats["fix_addressed"] += len(fix.addressed)
    try:
        ast.parse(fix.code)
    except SyntaxError as exc:
        stats["fix_invalid"] += 1
        failures.append({"file": name, "error": f"fixed code does not parse: {exc}"})
        return
    diff = unified_diff(code, fix.code, name)
    try:
        if apply_unified_diff(code, diff).rstrip("\n") != fix.code.rstrip("\n"):
            raise ValueError("round trip mismatch")
    except ValueError as exc:
        stats["diff_fail"] += 1
        failures.append({"file": name, "error": f"diff: {exc}"})
    before, after = public_names(code), public_names(fix.code)
    if before is not None and after is not None and not before <= after:
        stats["api_broken"] += 1
        failures.append({"file": name, "error": f"public names lost: {sorted(before - after)}"})
    after_findings = static_scan(SourceFile(path=name, language="python", content=fix.code))
    _, unresolved, new = compare_findings(findings, after_findings)
    stats["fix_still_present"] += sum(1 for fid in fix.addressed if fid in unresolved)
    stats["fix_new_findings"] += len(new)
    if new:
        failures.append({"file": name, "error": "fix introduced: " + ", ".join(f"{f.rule_id}@{f.line}" for f in new)})


# ---------------------------------------------------------------- main

def scan(name: str, code: str, timings: list, crashes: list) -> list:
    t0 = time.perf_counter()
    try:
        findings = static_scan(SourceFile(path=name, language="python", content=code))
    except Exception as exc:  # noqa: BLE001
        crashes.append({"file": name, "error": repr(exc), "trace": traceback.format_exc()[-800:]})
        findings = []
    timings.append(time.perf_counter() - t0)
    return findings


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", default="run")
    ap.add_argument("--stdlib", default=str(ROOT.parent / ".tools" / "python" / "tools" / "Lib"))
    ap.add_argument("--stdlib-limit", type=int, default=None)
    ap.add_argument("--show-misses", action="store_true")
    args = ap.parse_args()

    crashes: list = []
    fix_stats: Counter = Counter()
    fix_failures: list = []
    report: dict = {"label": args.label}

    # SecurityEval
    timings: list = []
    se = load_securityeval()
    detected = matched = 0
    per_cwe: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    misses = []
    for sid, cwe, code in se:
        findings = scan(sid, code, timings, crashes)
        found = {norm_cwe(f.cwe) for f in findings if f.cwe}
        hit = bool(findings)
        match = cwe_match(cwe, found)
        detected += hit
        matched += match
        per_cwe[cwe][0] += 1
        per_cwe[cwe][1] += hit
        per_cwe[cwe][2] += match
        if not match:
            misses.append((sid, sorted(found)))
        check_fix(sid, code, findings, fix_stats, fix_failures)
    report["securityeval"] = {
        "samples": len(se), "detected": detected, "cwe_matched": matched,
        "detect_rate": round(detected / len(se), 3), "cwe_match_rate": round(matched / len(se), 3),
        "cwes_covered": sum(1 for v in per_cwe.values() if v[2]), "cwes_total": len(per_cwe),
        "misses": [m[0] for m in misses],
    }

    # Bandit examples
    bd = load_bandit()
    pos = [b for b in bd if b[1] > 0]
    neg = [b for b in bd if b[1] == 0]
    file_hits = 0
    expected_total = found_total = 0
    neg_alarms = 0
    bandit_misses = []
    for name, count, code in bd:
        mat = material(scan("bandit/" + name, code, timings, crashes))
        if count > 0:
            file_hits += bool(mat)
            expected_total += count
            found_total += min(len(mat), count)
            if not mat:
                bandit_misses.append(name)
        elif mat:
            neg_alarms += 1
        check_fix("bandit/" + name, code, scan(name, code, [], crashes), fix_stats, fix_failures)
    report["bandit"] = {
        "files": len(bd), "positive_files": len(pos), "negative_files": len(neg),
        "file_recall": round(file_hits / max(1, len(pos)), 3),
        "issue_recall": round(found_total / max(1, expected_total), 3),
        "negative_file_alarms": neg_alarms, "missed_files": bandit_misses,
    }

    # Benign corpus
    std = load_stdlib(Path(args.stdlib), args.stdlib_limit)
    std_timings: list = []
    lines = 0
    rule_counts: Counter = Counter()
    for name, code in std:
        lines += code.count("\n") + 1
        findings = scan("stdlib/" + name, code, std_timings, crashes)
        rule_counts.update(f.rule_id for f in material(findings))
        check_fix("stdlib/" + name, code, findings, fix_stats, fix_failures)
    total_alarms = sum(rule_counts.values())
    report["stdlib"] = {
        "files": len(std), "kloc": round(lines / 1000, 1),
        "medium_plus_alarms": total_alarms, "alarms_per_kloc": round(total_alarms / max(1, lines / 1000), 3),
        "top_rules": rule_counts.most_common(12),
        "scan_seconds": round(sum(std_timings), 2),
        "kloc_per_second": round(lines / 1000 / max(1e-9, sum(std_timings)), 1),
        "slowest_ms": round(max(std_timings, default=0) * 1000, 1),
    }
    report["fixer"] = dict(fix_stats)
    report["crashes"] = crashes
    report["fix_failures"] = fix_failures[:40]

    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / f"{args.label}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    s, b, st = report["securityeval"], report["bandit"], report["stdlib"]
    print(f"== {args.label}")
    print(f"SecurityEval  detect {s['detect_rate']:.1%}  CWE-match {s['cwe_match_rate']:.1%}  "
          f"CWEs covered {s['cwes_covered']}/{s['cwes_total']}")
    print(f"Bandit        file recall {b['file_recall']:.1%}  issue recall {b['issue_recall']:.1%}  "
          f"alarms on clean examples {b['negative_file_alarms']}/{b['negative_files']}")
    print(f"Stdlib        {st['files']} files, {st['kloc']} KLOC, {st['alarms_per_kloc']} Medium+ alarms/KLOC, "
          f"{st['kloc_per_second']} KLOC/s, slowest file {st['slowest_ms']} ms")
    print(f"              top: {st['top_rules'][:8]}")
    print(f"Fixer         {dict(fix_stats)}")
    print(f"Crashes       {len(crashes)}")
    if args.show_misses:
        print("SecurityEval misses:", " ".join(s["misses"]))
        print("Bandit missed files:", " ".join(b["missed_files"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
