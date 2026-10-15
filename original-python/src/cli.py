"""Command line entry point: python -m src.cli <path | git-url | -> [options]"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Any

from .config import get_settings
from .models import AuditReport, Severity
from .orchestrator import AuditOrchestrator
from .repo import apply_patches, load_source, open_pull_request, write_report_files


def _progress(event: str, data: dict[str, Any]) -> None:
    if event == "start":
        print(f"Auditing {data['files']} file(s) in {data['mode']} mode")
    elif event == "scan_done":
        print(f"  scanner   {data['file']}: {data['findings']} finding(s)")
    elif event == "review":
        print(f"  reviewer  {data['file']}: pass {data['iteration']}, confidence {data['confidence']:.0%} ({data['verdict']})")
    elif event == "error":
        print(f"  error     {data['file']}: {data['error']}", file=sys.stderr)


def print_summary(report: AuditReport) -> None:
    print()
    print(f"Files scanned: {report.files_scanned}   Findings: {report.total_findings}   Patched files: {report.patched_files}")
    print("Severity: " + "  ".join(f"{k} {v}" for k, v in report.severity_counts.items()))
    if report.average_confidence is not None:
        print(f"Average reviewer confidence: {report.average_confidence:.0%}")
    for f in sorted(report.findings, key=lambda f: (-f.severity.rank, f.file, f.line))[:25]:
        print(f"  [{f.severity.value:<8}] {f.file}:{f.line}  {f.title}  ({f.rule_id})")
    if report.total_findings > 25:
        print(f"  ... {report.total_findings - 25} more in report.json")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="agentx", description="Nebius-AgentX security and performance audit")
    p.add_argument("source", help="Local path, Git URL, or '-' to read code from stdin")
    p.add_argument("--filename", default=None, help="File name for stdin code, e.g. app.py")
    p.add_argument("--iterations", type=int, default=2, help="Max Refactor/Reviewer passes per file")
    p.add_argument("--threshold", type=float, default=0.8, help="Reviewer confidence needed to approve")
    p.add_argument("--offline", action="store_true", help="Skip Nebius and use only the rule engine")
    p.add_argument("--out", default="agentx-report", help="Directory for report.json and patches")
    p.add_argument("--apply", action="store_true", help="Write reviewed patches and commit them on a new branch")
    p.add_argument("--branch", default="agentx/security-fixes")
    p.add_argument("--pr", action="store_true", help="Push the branch and open a GitHub PR (needs GITHUB_TOKEN)")
    p.add_argument("--fail-on", choices=[s.value.lower() for s in Severity],
                   help="Exit with code 2 if any finding is at or above this severity (for CI)")
    args = p.parse_args(argv)

    snippet = args.source == "-"
    source = sys.stdin.read() if snippet else args.source
    loaded = load_source(source, filename=args.filename, snippet=snippet, shallow=not args.pr)
    try:
        if not loaded.files:
            print(f"No supported source files found in {loaded.label}", file=sys.stderr)
            return 1
        orchestrator = AuditOrchestrator(
            max_iterations=args.iterations, approve_threshold=args.threshold,
            use_llm=not args.offline, progress=_progress,
        )
        report = asyncio.run(orchestrator.audit_files(loaded.files, loaded.label))
        paths = write_report_files(report, Path(args.out))
        print_summary(report)
        print(f"\nReport: {paths['report']}\nPatch:  {paths['patch']}")

        if args.apply or args.pr:
            if loaded.root is None:
                print("--apply and --pr need a path or Git URL, not stdin.", file=sys.stderr)
                return 1
            applied = apply_patches(report, loaded.root, branch=args.branch)
            print(f"Applied {len(applied.files)} patch(es)" + (f" on branch {applied.branch}" if applied.branch else ""))
            if args.pr:
                if not (applied.branch and loaded.remote_url):
                    print("--pr needs a GitHub URL as the source and at least one applied patch.", file=sys.stderr)
                    return 1
                url = open_pull_request(loaded.root, loaded.remote_url, applied.branch, applied.base, report,
                                        get_settings().github_token)
                print(f"Pull request: {url}")

        if args.fail_on:
            floor = Severity.parse(args.fail_on).rank
            if any(f.severity.rank >= floor for f in report.findings):
                return 2
        return 0
    finally:
        loaded.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
