"""Deterministic, AST-guided fixes for the static rules the Scanner agent reports.

The Refactor agent applies these first, then asks the model to handle whatever is left, so
a patch exists even when Nebius is unreachable and the model starts from a safer baseline.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from .models import Finding, SourceFile
from .pyanalysis import ImportMap, is_secret_name, looks_like_secret
from .scanner import _is_mutable_default, call_name, compare_findings, is_const, secret_target, static_scan

FIXABLE = {"PY001", "PY002", "PY004", "PY005", "PY006", "PY008", "PY009", "PY010", "PY012", "PY014"}
_EXCEPT = re.compile(r"except\s*:")


@dataclass
class FixResult:
    code: str
    addressed: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.addressed)


@dataclass
class _Edit:
    start: int
    end: int
    text: str
    ids: list[str] = field(default_factory=list)
    imports: set[str] = field(default_factory=set)


class _Source:
    """Maps ast (line, utf-8 byte column) positions to string offsets."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.lines = [line for line in re.split(r"(?<=\n)", text) if line]
        self.starts: list[int] = []
        pos = 0
        for line in self.lines:
            self.starts.append(pos)
            pos += len(line)

    def line_start(self, lineno: int) -> int:
        return self.starts[lineno - 1] if 0 < lineno <= len(self.starts) else len(self.text)

    def offset(self, lineno: int, col_bytes: int) -> int:
        if not 0 < lineno <= len(self.lines):
            return len(self.text)
        line = self.lines[lineno - 1]
        col = len(line.encode("utf-8")[:col_bytes].decode("utf-8", errors="ignore"))
        return self.starts[lineno - 1] + col

    def span(self, node: ast.AST) -> tuple[int, int]:
        return self.offset(node.lineno, node.col_offset), self.offset(node.end_lineno, node.end_col_offset)  # type: ignore[attr-defined]

    def segment(self, node: ast.AST) -> str:
        start, end = self.span(node)
        return self.text[start:end]


def ensure_imports(code: str, modules: set[str]) -> str:
    """Add `import x` lines for modules not already bound at module level."""
    if not modules:
        return code
    tree = ast.parse(code)
    bound: set[str] = set()
    insert_after = 0
    for i, node in enumerate(tree.body):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            insert_after = node.end_lineno or node.lineno
            if isinstance(node, ast.Import):
                bound.update(a.asname or a.name.split(".")[0] for a in node.names)
        elif i == 0 and isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            insert_after = node.end_lineno or node.lineno
    missing = sorted(m for m in modules if m not in bound)
    if not missing:
        return code
    lines = [line for line in re.split(r"(?<=\n)", code) if line]
    if insert_after and not lines[insert_after - 1].endswith("\n"):
        lines[insert_after - 1] += "\n"
    lines.insert(insert_after, "".join(f"import {m}\n" for m in missing))
    return "".join(lines)


def _docstring(node: ast.stmt) -> bool:
    return isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)


def apply_rule_fixes(source: str, findings: list[Finding]) -> FixResult:
    if source.startswith("﻿"):  # keep a byte-order mark but fix the code after it
        inner = apply_rule_fixes(source[1:], findings)
        return FixResult("﻿" + inner.code if inner.addressed else source, inner.addressed, inner.notes)
    wanted: dict[tuple[str, int], list[Finding]] = {}
    for f in findings:
        if f.source == "static" and f.rule_id in FIXABLE:
            wanted.setdefault((f.rule_id, f.line), []).append(f)
    if not wanted:
        return FixResult(source)
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return FixResult(source, notes=["Rule engine skipped this file because it does not parse."])

    src = _Source(source)
    imports = ImportMap(tree)
    edits: list[_Edit] = []
    notes: list[str] = []

    def take(rule: str, line: int) -> list[str]:
        return [f.id for f in wanted.pop((rule, line), [])]

    def fix_call(node: ast.Call) -> None:
        name = imports.resolve(call_name(node.func))  # `from os import system` -> os.system
        kw = {k.arg: k for k in node.keywords if k.arg}
        line = node.lineno
        if ("PY008", line) in wanted:
            for k in node.keywords:
                if k.arg and is_secret_name(k.arg) and isinstance(k.value, ast.Constant) and looks_like_secret(k.value.value, 4):
                    env = re.sub(r"[^A-Za-z0-9]+", "_", k.arg).upper()
                    edits.append(_Edit(*src.span(k.value), f'os.environ.get("{env}", "")', take("PY008", line), {"os"}))
        if name == "hashlib.new" and ("PY005", line) in wanted and node.args and isinstance(node.args[0], ast.Constant):
            edits.append(_Edit(*src.span(node.args[0]), '"sha256"', take("PY005", line)))
        if ("PY001", line) in wanted:
            if name == "eval" and len(node.args) == 1 and not node.keywords:
                edits.append(_Edit(*src.span(node.func), "ast.literal_eval", take("PY001", line), {"ast"}))
            elif name == "exec":
                notes.append(f"Line {line}: exec() needs a manual redesign; left for the model.")
        constant_cmd = bool(node.args) and isinstance(node.args[0], ast.Constant)
        if ("PY002", line) in wanted and constant_cmd:
            notes.append(f"Line {line}: fixed shell command left as is; it takes no input and may rely on shell syntax.")
        elif ("PY002", line) in wanted:
            if name == "os.system" and len(node.args) == 1 and not node.keywords:
                arg = src.segment(node.args[0])
                edits.append(_Edit(*src.span(node), f"subprocess.run(shlex.split({arg}), check=False).returncode",
                                   take("PY002", line), {"subprocess", "shlex"}))
            elif name.startswith("subprocess.") and "shell" in kw:
                if node.args and not isinstance(node.args[0], (ast.List, ast.Tuple)):
                    edits.append(_Edit(*src.span(node.args[0]), f"shlex.split({src.segment(node.args[0])})", [], {"shlex"}))
                edits.append(_Edit(*src.span(kw["shell"].value), "False", take("PY002", line)))
        if name == "yaml.load" and ("PY004", line) in wanted and node.args:
            edits.append(_Edit(*src.span(node), f"yaml.safe_load({src.segment(node.args[0])})", take("PY004", line), {"yaml"}))
        if name in ("hashlib.md5", "hashlib.sha1") and ("PY005", line) in wanted:
            edits.append(_Edit(*src.span(node.func), "hashlib.sha256", take("PY005", line), {"hashlib"}))
        if "verify" in kw and ("PY006", line) in wanted and is_const(kw["verify"].value, False):
            edits.append(_Edit(*src.span(kw["verify"].value), "True", take("PY006", line)))
        if name.split(".")[-1] == "run" and "debug" in kw and ("PY014", line) in wanted:
            edits.append(_Edit(*src.span(kw["debug"].value), "False", take("PY014", line)))
        if name == "time.sleep" and ("PY012", line) in wanted:
            args = ", ".join(src.segment(a) for a in node.args)
            edits.append(_Edit(*src.span(node), f"await asyncio.sleep({args})", take("PY012", line), {"asyncio"}))

    def fix_defaults(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        a = fn.args
        positional = [*a.posonlyargs, *a.args]
        pairs = list(zip(positional[len(positional) - len(a.defaults):], a.defaults))
        pairs += [(arg, d) for arg, d in zip(a.kwonlyargs, a.kw_defaults) if d is not None]
        targets = [(arg, d) for arg, d in pairs if ("PY010", d.lineno) in wanted and _is_mutable_default(d)]
        if not targets or not fn.body:
            return
        first = fn.body[0]
        if src.lines[first.lineno - 1][: first.col_offset].strip():
            notes.append(f"Line {fn.lineno}: one-line function; mutable default left for the model.")
            return
        if _docstring(first):
            insert_line = (first.end_lineno or first.lineno) + 1
            anchor = fn.body[1] if len(fn.body) > 1 else first
        else:
            insert_line, anchor = first.lineno, first
        indent = re.match(r"[ \t]*", src.lines[anchor.lineno - 1]).group(0)  # type: ignore[union-attr]
        unit = "\t" if indent.startswith("\t") else "    "
        block = "".join(f"{indent}if {arg.arg} is None:\n{indent}{unit}{arg.arg} = {src.segment(d)}\n" for arg, d in targets)
        pos = src.line_start(insert_line)
        if pos == len(source) and not source.endswith("\n"):
            block = "\n" + block
        for arg, d in targets:
            edits.append(_Edit(*src.span(d), "None", take("PY010", d.lineno)))
        edits.append(_Edit(pos, pos, block))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fix_call(node)
        elif isinstance(node, ast.ExceptHandler) and node.type is None and ("PY009", node.lineno) in wanted:
            start = src.offset(node.lineno, node.col_offset)
            m = _EXCEPT.match(source, start)
            if m:
                edits.append(_Edit(start, m.end(), "except Exception:", take("PY009", node.lineno)))
        elif isinstance(node, (ast.Assign, ast.AnnAssign)) and ("PY008", node.lineno) in wanted:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            name = secret_target(targets, node.value)
            if name and node.value is not None:
                env = re.sub(r"[^A-Za-z0-9]+", "_", name).upper()
                edits.append(_Edit(*src.span(node.value), f'os.environ.get("{env}", "")', take("PY008", node.lineno), {"os"}))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fix_defaults(node)

    edits.sort(key=lambda e: (e.start, e.end), reverse=True)
    code = source
    addressed: list[str] = []
    imports: set[str] = set()
    floor = len(source) + 1
    for e in edits:
        if e.end > floor:
            notes.append("Skipped an overlapping fix; the model will handle it.")
            continue
        code = code[: e.start] + e.text + code[e.end :]
        floor = e.start
        addressed.extend(e.ids)
        imports |= e.imports
    if not addressed:
        return FixResult(source, notes=notes)
    try:
        code = ensure_imports(code, imports)
        ast.parse(code)
    except (SyntaxError, ValueError, RecursionError) as exc:
        return FixResult(source, notes=[*notes, f"Rule fixes produced invalid code ({exc}); discarded."])
    # Self-check: only claim findings whose rule actually stopped firing.
    after = static_scan(SourceFile(path="patched.py", language="python", content=code))
    _, still_open, _ = compare_findings([f for f in findings if f.source == "static"], after)
    claimed = sorted(set(addressed) - set(still_open))
    if len(claimed) < len(set(addressed)):
        notes.append("Some rule fixes reduced but did not remove a finding; left for the model to finish.")
    return FixResult(code, claimed, notes)
