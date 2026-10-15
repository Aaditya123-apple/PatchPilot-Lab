"""The three collaborating agents: Scanner, Refactor and Reviewer.

Each agent works without a model (static rules, rule-based fixes, automated checks) and adds
Nebius-hosted NVIDIA model reasoning on top when an LLM client is supplied.
"""

from __future__ import annotations

import ast
import json
import re
from typing import Any, Protocol, Sequence

from .diffing import apply_unified_diff, diff_stats, unified_diff
from .fixers import FixResult, apply_rule_fixes
from .models import Category, CodeChunk, Finding, Patch, Review, Severity, SourceFile
from .nebius_client import ChatResult, NebiusError, extract_code_blocks, parse_json_payload, strip_reasoning
from .scanner import chunk_source, compare_findings, static_scan


class LLM(Protocol):
    available: bool

    async def chat(self, messages: Sequence[dict[str, str]], **kwargs: Any) -> ChatResult: ...

    async def chat_json(self, messages: Sequence[dict[str, str]], **kwargs: Any) -> Any: ...


LANG_ALIASES = {
    "python": {"python", "py", "python3"},
    "javascript": {"javascript", "js", "jsx", "node"},
    "typescript": {"typescript", "ts", "tsx"},
}
_CWE = re.compile(r"CWE-\d+", re.I)


def number_lines(text: str, start: int = 1) -> str:
    lines = text.splitlines()
    width = len(str(start + len(lines)))
    return "\n".join(f"{i:>{width}} | {line}" for i, line in enumerate(lines, start))


_PARSE_ERRORS = (SyntaxError, ValueError, RecursionError, MemoryError)


def public_names(code: str) -> set[str] | None:
    try:
        tree = ast.parse(code)
    except _PARSE_ERRORS:
        return None
    return {
        n.name for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and not n.name.startswith("_")
    }


def is_valid_code(code: str, language: str) -> bool:
    if not code.strip():
        return False
    if language == "python":
        try:
            ast.parse(code)
        except _PARSE_ERRORS:
            return False
    return True


def _norm(text: str) -> str:
    return " ".join(text.split())


def _finding_line(f: Finding) -> str:
    return f"- [{f.id}] line {f.line} · {f.severity.value} · {f.title}: {f.recommendation or f.description}"


# ---------------------------------------------------------------- Scanner

SCANNER_SYSTEM = (
    "You are the Scanner agent in Nebius-AgentX, an autonomous security and performance auditor. "
    "Report only concrete, exploitable or measurable problems that you can tie to a specific line. "
    "Skip style preferences. Reply with JSON only."
)


class ScannerAgent:
    """Finds security flaws and performance bottlenecks with static rules plus model review."""

    def __init__(self, llm: LLM | None = None, *, chunk_lines: int = 120, max_llm_findings: int = 8) -> None:
        self.llm = llm
        self.chunk_lines = chunk_lines
        self.max_llm_findings = max_llm_findings

    def messages(self, chunk: CodeChunk, known: list[Finding]) -> list[dict[str, str]]:
        already = [f"line {f.line}: {f.title}" for f in known if chunk.start_line <= f.line <= chunk.end_line]
        user = (
            f"File: {chunk.file} ({chunk.language}), lines {chunk.start_line}-{chunk.end_line}.\n"
            f"Static analysis already reported: {'; '.join(already) if already else 'nothing'}. Do not repeat those.\n\n"
            'Return {"findings": [{"line": <int>, "title": <str>, "severity": "Low|Medium|High|Critical", '
            '"category": "Security|Performance|Reliability|Maintainability", "cwe": "CWE-<n> or null", '
            '"description": <str>, "recommendation": <str>}]}. Return {"findings": []} if the code is fine.\n\n'
            f"Code (line numbers on the left):\n{number_lines(chunk.content, chunk.start_line)}"
        )
        return [{"role": "system", "content": SCANNER_SYSTEM}, {"role": "user", "content": user}]

    def parse(self, payload: Any, chunk: CodeChunk, lines: list[str], known: list[Finding]) -> list[Finding]:
        if isinstance(payload, dict):
            items = payload.get("findings", [])
        elif isinstance(payload, list):
            items = payload
        else:
            items = []
        out: list[Finding] = []
        for n, item in enumerate(items[: self.max_llm_findings] if isinstance(items, list) else []):
            if not isinstance(item, dict):
                continue
            try:
                line = int(item.get("line"))
            except (TypeError, ValueError):
                continue
            title = str(item.get("title") or "").strip()
            if not title or not chunk.start_line <= line <= chunk.end_line:
                continue
            category = Category.parse(item.get("category"))
            if any(abs(f.line - line) <= 1 and f.category == category for f in [*known, *out]):
                continue
            cwe = _CWE.search(str(item.get("cwe") or ""))
            rule_id = f"LLM-{category.value[:4].upper()}"
            out.append(Finding(
                id=f"{rule_id}@{chunk.file}:{line}:{n}",
                file=chunk.file,
                line=line,
                rule_id=rule_id,
                title=title[:120],
                description=str(item.get("description") or "").strip()[:600],
                severity=Severity.parse(item.get("severity")),
                category=category,
                cwe=cwe.group(0).upper() if cwe else None,
                snippet=lines[line - 1].strip()[:240] if line <= len(lines) else "",
                recommendation=str(item.get("recommendation") or "").strip()[:600],
                source="llm",
            ))
        return out

    async def run(self, file: SourceFile) -> tuple[list[Finding], list[str]]:
        findings = static_scan(file)
        notes: list[str] = []
        if self.llm is not None:
            lines = file.content.splitlines()
            for chunk in chunk_source(file, max_lines=self.chunk_lines, overlap=10):
                try:
                    payload = await self.llm.chat_json(self.messages(chunk, findings), temperature=0.1, max_tokens=1800)
                except (NebiusError, ValueError) as exc:
                    notes.append(f"Scanner model call failed for lines {chunk.start_line}-{chunk.end_line}: {exc}")
                    continue
                findings.extend(self.parse(payload, chunk, lines, findings))
        findings.sort(key=lambda f: (-f.severity.rank, f.line, f.rule_id))
        return findings, notes


# ---------------------------------------------------------------- Refactor

REFACTOR_SYSTEM = (
    "You are the Refactor agent in Nebius-AgentX. Fix the listed security and performance findings with "
    "minimal, behavior-preserving edits. Keep public function and class names and signatures unless a "
    "finding requires a change. Add type hints to code you touch. Do not add placeholder comments or "
    "explanations inside the code."
)


class RefactorAgent:
    """Writes the patch: deterministic rule fixes first, then model edits for the rest."""

    def __init__(self, llm: LLM | None = None, *, max_lines: int = 800) -> None:
        self.llm = llm
        self.max_lines = max_lines

    def messages(self, file: SourceFile, findings: list[Finding], code: str, feedback: str | None) -> list[dict[str, str]]:
        fence = file.language if file.language != "text" else ""
        parts = [
            f"Fix these findings in {file.path}:",
            "\n".join(_finding_line(f) for f in findings),
            "",
            "The code below already includes deterministic fixes from the rule engine. Keep them.",
        ]
        if feedback:
            parts += ["", "Reviewer feedback on your previous attempt:", feedback]
        parts += [
            "",
            f"Reply with the complete updated file in one ```{fence} code block, followed by a ```json block: "
            '{"addressed": ["finding ids you fixed"], "explanation": "one short paragraph"}.',
            "",
            f"```{fence}\n{code}\n```",
        ]
        return [{"role": "system", "content": REFACTOR_SYSTEM}, {"role": "user", "content": "\n".join(parts)}]

    @staticmethod
    def parse(text: str, language: str) -> tuple[str | None, dict[str, Any]]:
        blocks = extract_code_blocks(strip_reasoning(text))
        aliases = LANG_ALIASES.get(language, {language})
        code: str | None = None
        meta: Any = {}
        for lang, body in blocks:
            if lang == "json":
                try:
                    meta = parse_json_payload(body)
                except ValueError:
                    meta = {}
            elif code is None and (lang in aliases or lang == ""):
                code = body
        if code is None:
            others = [body for lang, body in blocks if lang != "json"]
            code = max(others, key=len) if others else None
        return code, meta if isinstance(meta, dict) else {}

    def _budget(self, code: str) -> int:
        return int(min(8192, max(1024, len(code) / 3 * 1.6 + 600)))

    async def run(
        self, file: SourceFile, findings: list[Finding], feedback: str | None = None
    ) -> tuple[Patch | None, list[str]]:
        if not findings:
            return None, []
        fix = apply_rule_fixes(file.content, findings) if file.language == "python" else FixResult(file.content)
        notes = list(fix.notes)
        code = fix.code
        ids = {f.id for f in findings}
        addressed = set(fix.addressed)
        explanation: list[str] = []
        if fix.addressed:
            explanation.append(f"Rule engine fixed {len(fix.addressed)} finding(s) deterministically.")
        used_llm = False
        remaining = [f for f in findings if f.id not in addressed]
        if self.llm is not None and (remaining or feedback) and file.content.count("\n") <= self.max_lines:
            try:
                result = await self.llm.chat(
                    self.messages(file, findings, code, feedback), temperature=0.15, max_tokens=self._budget(code)
                )
                llm_code, meta = self.parse(result.content, file.language)
                lost = set()
                if llm_code and file.language == "python":
                    before, after = public_names(file.content), public_names(llm_code)
                    lost = (before - after) if before is not None and after is not None else set()
                if lost:
                    notes.append("Refactor model dropped public names (" + ", ".join(sorted(lost)) + "); kept the rule-engine patch.")
                elif llm_code and is_valid_code(llm_code, file.language):
                    if file.content.endswith("\n") and not llm_code.endswith("\n"):
                        llm_code += "\n"
                    code = llm_code
                    used_llm = True
                    claimed = meta.get("addressed", [])
                    addressed |= {str(i) for i in claimed if str(i) in ids} if isinstance(claimed, list) else set()
                    if meta.get("explanation"):
                        explanation.append(str(meta["explanation"]).strip())
                else:
                    notes.append("Refactor model returned no valid code; kept the rule-engine patch.")
            except NebiusError as exc:
                notes.append(f"Refactor model call failed: {exc}")
        elif self.llm is not None and remaining:
            notes.append(f"File is longer than {self.max_lines} lines; only rule-engine fixes were applied.")
        if code == file.content:
            return None, notes
        stats = diff_stats(file.content, code)
        source = "rules+llm" if used_llm and fix.addressed else ("llm" if used_llm else "rules")
        patch = Patch(
            file=file.path,
            original=file.content,
            patched=code,
            diff=unified_diff(file.content, code, file.path),
            addressed=sorted(addressed),
            explanation=" ".join(explanation),
            source=source,
            added=int(stats["added"]),
            removed=int(stats["removed"]),
        )
        return patch, notes


# ---------------------------------------------------------------- Reviewer

REVIEWER_SYSTEM = (
    "You are the Reviewer agent in Nebius-AgentX. Check whether a proposed patch fixes the listed findings "
    "without changing intended behavior or adding new risk. Be strict. Reply with JSON only."
)


class ReviewerAgent:
    """Verifies a patch with automated checks and, when available, a model review; outputs a confidence score."""

    def __init__(self, llm: LLM | None = None, *, approve_threshold: float = 0.8, revise_threshold: float = 0.5) -> None:
        self.llm = llm
        self.approve_threshold = approve_threshold
        self.revise_threshold = revise_threshold

    def automated_checks(self, file: SourceFile, findings: list[Finding], patch: Patch) -> tuple[dict[str, bool], list[str], list[str], list[Finding]]:
        checks: dict[str, bool] = {}
        try:
            rebuilt = apply_unified_diff(file.content, patch.diff)
            checks["diff_applies"] = rebuilt.rstrip("\r\n") == patch.patched.rstrip("\r\n")
        except ValueError:
            checks["diff_applies"] = False
        checks["syntax_valid"] = is_valid_code(patch.patched, file.language)
        if file.language == "python":
            before, after = public_names(file.content), public_names(patch.patched)
            checks["public_api_preserved"] = before is None or (after is not None and before <= after)
        checks["minimal_change"] = diff_stats(file.content, patch.patched)["changed_ratio"] <= 0.6

        after_findings = static_scan(SourceFile(path=file.path, language=file.language, content=patch.patched))
        resolved, unresolved, new = compare_findings(findings, after_findings)
        for f in findings:
            if f.source == "llm":
                (resolved if f.id in patch.addressed else unresolved).append(f.id)
        checks["no_new_issues"] = not new
        checks["findings_resolved"] = not unresolved
        return checks, resolved, unresolved, new

    def heuristic_confidence(self, checks: dict[str, bool], resolved: list[str], findings: list[Finding]) -> float:
        """Half structural checks, half severity-weighted share of findings resolved."""
        if not checks.get("diff_applies", True) or not checks.get("syntax_valid", True):
            return 0.0
        structural = [v for k, v in checks.items() if k != "findings_resolved"]
        total = sum(f.severity.rank for f in findings)
        done = sum(f.severity.rank for f in findings if f.id in resolved)
        resolved_ratio = done / total if total else 1.0
        return round(0.5 * resolved_ratio + 0.5 * (sum(structural) / len(structural)), 3)

    def messages(self, findings: list[Finding], patch: Patch, checks: dict[str, bool]) -> list[dict[str, str]]:
        diff = patch.diff if len(patch.diff) <= 12000 else patch.diff[:12000] + "\n... (diff truncated)"
        user = (
            f"File: {patch.file}\nFindings to fix:\n" + "\n".join(_finding_line(f) for f in findings) +
            f"\n\nAutomated checks: {json.dumps(checks)}\n\nPatch:\n```diff\n{diff}\n```\n\n"
            'Return {"confidence": <0.0-1.0>, "verdict": "approve|revise|reject", '
            '"unresolved": ["finding ids still present"], "notes": ["short, actionable feedback"]}.'
        )
        return [{"role": "system", "content": REVIEWER_SYSTEM}, {"role": "user", "content": user}]

    def verdict(self, confidence: float) -> str:
        if confidence >= self.approve_threshold:
            return "approve"
        return "revise" if confidence >= self.revise_threshold else "reject"

    async def run(self, file: SourceFile, findings: list[Finding], patch: Patch) -> Review:
        checks, resolved, unresolved, new = self.automated_checks(file, findings, patch)
        confidence = self.heuristic_confidence(checks, resolved, findings)
        notes: list[str] = []
        if new:
            notes.append("Patch introduced: " + "; ".join(f"line {f.line} {f.title}" for f in new))
        failed = [k for k, v in checks.items() if not v and k != "findings_resolved"]
        if failed:
            notes.append("Failed checks: " + ", ".join(failed))
        if self.llm is not None and confidence > 0:
            try:
                payload = await self.llm.chat_json(self.messages(findings, patch, checks), temperature=0.0, max_tokens=900)
                if isinstance(payload, dict):
                    llm_conf = float(payload.get("confidence", confidence))
                    llm_conf = min(1.0, max(0.0, llm_conf))
                    confidence = round(0.55 * confidence + 0.45 * llm_conf, 3)
                    ids = {f.id for f in findings}
                    extra = [str(i) for i in payload.get("unresolved", []) or [] if str(i) in ids]
                    for i in extra:
                        if i in resolved:
                            resolved.remove(i)
                        if i not in unresolved:
                            unresolved.append(i)
                    notes += [str(n).strip() for n in payload.get("notes", []) or [] if str(n).strip()][:6]
            except (NebiusError, ValueError, TypeError) as exc:
                notes.append(f"Reviewer model call failed, used automated checks only: {exc}")
        checks["findings_resolved"] = not unresolved
        verdict = self.verdict(confidence)
        critical_left = [f for f in findings if f.id in unresolved and f.severity is Severity.CRITICAL]
        if verdict == "approve" and critical_left:
            verdict = "revise"
            notes.append("Not approved: Critical finding still open: " + "; ".join(f"line {f.line} {f.title}" for f in critical_left))
        gates = [k for k in ("diff_applies", "syntax_valid", "public_api_preserved", "no_new_issues") if checks.get(k) is False]
        if verdict == "approve" and gates:
            verdict = "revise"
            notes.append("Not approved: failed hard check(s): " + ", ".join(gates))
        return Review(
            file=patch.file,
            confidence=confidence,
            verdict=verdict,  # type: ignore[arg-type]
            checks=checks,
            resolved=resolved,
            unresolved=unresolved,
            new_findings=new,
            notes=notes,
        )
