"""File discovery, AST-aware chunking and the static rule engine used by the Scanner agent."""

from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .models import Category, CodeChunk, Finding, Severity, SourceFile

LANGUAGES = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".go": "go", ".java": "java", ".rb": "ruby",
    ".php": "php", ".rs": "rust", ".cs": "csharp", ".c": "c", ".h": "c", ".cpp": "cpp",
    ".sh": "shell", ".yml": "yaml", ".yaml": "yaml",
}
IGNORED_DIRS = {
    "node_modules", "__pycache__", "venv", "env", "dist", "build", "site-packages",
    "target", "vendor", "coverage",
}


def detect_language(path: str) -> str:
    return LANGUAGES.get(Path(path).suffix.lower(), "text")


def discover_files(root: str | Path, *, max_files: int = 200, max_bytes: int = 200_000) -> list[SourceFile]:
    """Collect supported source files under root, skipping vendored, hidden and oversized files."""
    root = Path(root)
    if root.is_file():
        file = _read(root, root.name, max_bytes)
        return [file] if file else []
    files: list[SourceFile] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in IGNORED_DIRS and not d.startswith("."))
        for name in sorted(filenames):
            if len(files) >= max_files:
                return files
            path = Path(dirpath) / name
            file = _read(path, path.relative_to(root).as_posix(), max_bytes)
            if file:
                files.append(file)
    return files


def _read(path: Path, rel: str, max_bytes: int) -> SourceFile | None:
    language = detect_language(path.name)
    if language == "text":
        return None
    try:
        if path.stat().st_size > max_bytes:
            return None
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    return SourceFile(path=rel, language=language, content=content)


# ---------------------------------------------------------------- chunking

def chunk_source(file: SourceFile, *, max_lines: int = 120, overlap: int = 10) -> list[CodeChunk]:
    """Split a file into chunks of at most max_lines lines that together cover every line.

    Python files are split on top-level statement boundaries so a function is not cut in half
    unless it is longer than max_lines. Other languages use overlapping line windows.
    """
    if max_lines < 1:
        raise ValueError("max_lines must be at least 1")
    overlap = max(0, min(overlap, max_lines - 1))
    lines = file.content.splitlines()
    n = len(lines)
    if n == 0:
        return []
    spans = _python_spans(file.content, n, max_lines) if file.language == "python" else None
    if spans is None:
        spans = _window(1, n, max_lines, overlap)
    return [
        CodeChunk(file=file.path, language=file.language, start_line=s, end_line=e, content="\n".join(lines[s - 1 : e]))
        for s, e in spans
    ]


def _window(start: int, end: int, max_lines: int, overlap: int) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    s = start
    while True:
        e = min(end, s + max_lines - 1)
        spans.append((s, e))
        if e >= end:
            return spans
        s = e - overlap + 1


def _python_spans(source: str, n: int, max_lines: int) -> list[tuple[int, int]] | None:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    starts = {1}
    for node in tree.body:
        decorators = [d.lineno for d in getattr(node, "decorator_list", [])]
        starts.add(min([node.lineno, *decorators]))
    ordered = sorted(s for s in starts if s <= n)
    segments = [(s, (ordered[i + 1] - 1) if i + 1 < len(ordered) else n) for i, s in enumerate(ordered)]
    spans: list[tuple[int, int]] = []
    cur: tuple[int, int] | None = None
    for s, e in segments:
        if e < s:
            continue
        if e - s + 1 > max_lines:
            if cur:
                spans.append(cur)
                cur = None
            spans.extend(_window(s, e, max_lines, 0))
        elif cur is None:
            cur = (s, e)
        elif e - cur[0] + 1 <= max_lines:
            cur = (cur[0], e)
        else:
            spans.append(cur)
            cur = (s, e)
    if cur:
        spans.append(cur)
    return spans



# ---------------------------------------------------------------- static rules

from .pyanalysis import (  # noqa: E402  (re-exported for fixers and agents)
    analyze_python,
    call_name,
    is_const,
    is_dynamic_string as _is_dynamic_string,
    is_mutable_default as _is_mutable_default,
    secret_target,
)
from .rules import RULES, Rule  # noqa: E402

__all__ = [
    "LANGUAGES", "RULES", "Rule", "call_name", "chunk_source", "detect_language", "discover_files",
    "is_const", "make_finding", "secret_target", "static_scan", "_is_dynamic_string", "_is_mutable_default",
]

_REGEX_RULES: list[tuple[str, re.Pattern[str], set[str] | None]] = [
    ("JS001", re.compile(r"(?<![\w.])eval\s*\("), {"javascript", "typescript"}),
    ("JS002", re.compile(r"\.innerHTML\s*=|\.outerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\("), {"javascript", "typescript"}),
    ("JS003", re.compile(r"\bexecSync\s*\(|require\(\s*['\"]child_process['\"]\s*\)|from\s+['\"]child_process['\"]"), {"javascript", "typescript"}),
    ("GEN001", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), None),
    ("GEN002", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), None),
    ("GEN003", re.compile(r"""(?i)\b(?:password|passwd|secret|api_?key|access_?token|auth_?token)\b\s*[:=]\s*["'][^"'\s]{6,}["']"""), None),
    ("GEN004", re.compile("[‪-‮⁦-⁩]"), None),
]


def make_finding(file: SourceFile, rule_id: str, line: int, lines: list[str], severity: Severity | None = None) -> Finding:
    rule = RULES[rule_id]
    snippet = lines[line - 1].strip() if 0 < line <= len(lines) else ""
    return Finding(
        id=f"{rule_id}@{file.path}:{line}",
        file=file.path,
        line=line,
        rule_id=rule_id,
        title=rule.title,
        description=rule.description,
        severity=severity or rule.severity,
        category=rule.category,
        cwe=rule.cwe,
        snippet=snippet[:240],
        recommendation=rule.recommendation,
        source="static",
    )


_SUPPRESS = re.compile(r"#\s*(?:nosec\b|patchpilot:\s*ignore\b)", re.I)  # reviewed-and-accepted lines


def _norm(text: str) -> str:
    return " ".join(text.split())


def compare_findings(before: list[Finding], after: list[Finding]) -> tuple[list[str], list[str], list[Finding]]:
    """Match static findings before and after a patch, rule by rule.

    A finding counts as resolved only if its rule fires fewer times afterwards. Matching is
    by line text first; a rule that still fires on an edited line keeps the original finding
    unresolved instead of letting the edit pass as a fix. Returns (resolved ids, unresolved ids,
    findings that are genuinely new).
    """
    by_rule_before: dict[str, list[Finding]] = {}
    by_rule_after: dict[str, list[Finding]] = {}
    for f in before:
        if f.source == "static":
            by_rule_before.setdefault(f.rule_id, []).append(f)
    for f in after:
        by_rule_after.setdefault(f.rule_id, []).append(f)
    resolved: list[str] = []
    unresolved: list[str] = []
    new: list[Finding] = []
    for rule in sorted(set(by_rule_before) | set(by_rule_after)):
        unmatched = list(by_rule_after.get(rule, []))
        gone: list[Finding] = []
        for f in by_rule_before.get(rule, []):
            match = next((a for a in unmatched if _norm(a.snippet) == _norm(f.snippet)), None)
            if match is not None:
                unmatched.remove(match)
                unresolved.append(f.id)
            else:
                gone.append(f)
        carried = min(len(unmatched), len(gone))
        unresolved += [f.id for f in gone[:carried]]
        resolved += [f.id for f in gone[carried:]]
        new += unmatched[carried:]
    return resolved, unresolved, new


def static_scan(file: SourceFile) -> list[Finding]:
    """Run the deterministic rule engine on one file."""
    lines = file.content.splitlines()
    hits: dict[tuple[int, str], Severity | None] = {}
    parsed = False
    if file.language == "python":
        result = analyze_python(file.content)
        if result is not None:
            hits.update(result)
            parsed = True
    for rule_id, pattern, languages in _REGEX_RULES:
        if languages is not None and file.language not in languages:
            continue
        if rule_id == "GEN003" and parsed:
            continue  # the AST rule PY008 covers Python secrets with fewer false positives
        if not pattern.search(file.content):
            continue
        for i, line in enumerate(lines, 1):
            if pattern.search(line):
                hits.setdefault((i, rule_id), None)
    findings = [
        make_finding(file, rule_id, line, lines, sev)
        for (line, rule_id), sev in hits.items()
        if not (0 < line <= len(lines) and _SUPPRESS.search(lines[line - 1]))
    ]
    findings.sort(key=lambda f: (-f.severity.rank, f.line, f.rule_id))
    return findings