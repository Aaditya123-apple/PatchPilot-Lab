"""Runs the Scanner → Refactor → Reviewer loop across files with bounded concurrency."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Any, Callable

from .agent import RefactorAgent, ReviewerAgent, ScannerAgent
from .config import get_settings
from .models import AuditReport, FileResult, Finding, Review, SourceFile
from .nebius_client import NebiusClient
from .repo import load_source

ProgressCallback = Callable[[str, dict[str, Any]], None]


class AuditOrchestrator:
    """Coordinates the three agents.

    For each file the Scanner reports findings, the Refactor agent proposes a patch and the
    Reviewer scores it. A patch that is not approved goes back to the Refactor agent with the
    Reviewer's notes, up to `max_iterations` times; the best-scoring patch is kept.
    """

    def __init__(
        self,
        client: Any | None = None,
        *,
        max_iterations: int = 2,
        approve_threshold: float = 0.8,
        use_llm: bool = True,
        max_concurrency: int | None = None,
        progress: ProgressCallback | None = None,
    ) -> None:
        self.client = client if client is not None else NebiusClient()
        llm = self.client if use_llm and getattr(self.client, "available", False) else None
        self.mode = "nebius" if llm is not None else "offline"
        self.scanner = ScannerAgent(llm)
        self.refactor = RefactorAgent(llm)
        self.reviewer = ReviewerAgent(llm, approve_threshold=approve_threshold)
        self.max_iterations = max(1, max_iterations)
        self.max_concurrency = max_concurrency or get_settings().max_concurrency
        self.progress = progress

    def _emit(self, event: str, **data: Any) -> None:
        if self.progress is None:
            return
        try:
            self.progress(event, data)
        except Exception:  # a broken UI callback must not abort the audit
            pass

    @staticmethod
    def _feedback(review: Review, findings: list[Finding]) -> str:
        by_id = {f.id: f for f in findings}
        lines = [f"Confidence {review.confidence:.2f}, verdict {review.verdict}."]
        for fid in review.unresolved:
            f = by_id.get(fid)
            if f:
                lines.append(f"Still unresolved: [{fid}] line {f.line} {f.title}")
        lines += review.notes
        return "\n".join(lines)

    async def process_file(self, file: SourceFile) -> FileResult:
        result = FileResult(file=file.path, language=file.language)
        try:
            self._emit("scan_start", file=file.path)
            findings, notes = await self.scanner.run(file)
            result.findings = findings
            result.notes += notes
            self._emit("scan_done", file=file.path, findings=len(findings))
            if not findings:
                return result
            feedback: str | None = None
            for iteration in range(1, self.max_iterations + 1):
                self._emit("refactor", file=file.path, iteration=iteration)
                patch, notes = await self.refactor.run(file, findings, feedback)
                result.notes += notes
                if patch is None:
                    break
                review = await self.reviewer.run(file, findings, patch)
                result.iterations = iteration
                self._emit("review", file=file.path, iteration=iteration, confidence=review.confidence, verdict=review.verdict)
                if result.review is None or review.confidence >= result.review.confidence:
                    result.patch, result.review = patch, review
                if review.verdict == "approve" or self.refactor.llm is None:
                    break  # without a model the rule engine is deterministic, so retrying changes nothing
                feedback = self._feedback(review, findings)
        except Exception as exc:  # isolate failures so one bad file does not sink the whole audit
            result.error = f"{type(exc).__name__}: {exc}"
            self._emit("error", file=file.path, error=result.error)
        finally:
            self._emit("file_done", file=file.path)
        return result

    async def audit_files(self, files: list[SourceFile], source: str) -> AuditReport:
        started = datetime.now(timezone.utc)
        t0 = time.perf_counter()
        sem = asyncio.Semaphore(self.max_concurrency)

        async def guarded(f: SourceFile) -> FileResult:
            async with sem:
                return await self.process_file(f)

        self._emit("start", files=len(files), mode=self.mode)
        results = await asyncio.gather(*(guarded(f) for f in files))
        models = list(getattr(self.client, "models_used", [])) if self.mode == "nebius" else []
        report = AuditReport(
            source=source,
            mode=self.mode,  # type: ignore[arg-type]
            models_used=models,
            started_at=started,
            duration_s=round(time.perf_counter() - t0, 2),
            files_scanned=len(files),
            results=list(results),
        )
        self._emit("done", findings=report.total_findings, patched=report.patched_files)
        return report

    async def audit(self, source: str, *, filename: str | None = None, snippet: bool = False) -> AuditReport:
        loaded = await asyncio.to_thread(load_source, source, filename=filename, snippet=snippet)
        try:
            if not loaded.files:
                raise ValueError(f"No supported source files found in {loaded.label}")
            return await self.audit_files(loaded.files, loaded.label)
        finally:
            loaded.cleanup()


def run_audit(source: str, *, filename: str | None = None, snippet: bool = False, **kwargs: Any) -> AuditReport:
    """Synchronous convenience wrapper."""
    return asyncio.run(AuditOrchestrator(**kwargs).audit(source, filename=filename, snippet=snippet))
