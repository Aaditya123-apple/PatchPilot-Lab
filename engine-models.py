"""Typed data passed between the agents, the API and the UI."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, computed_field


class Severity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    @property
    def rank(self) -> int:
        return {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}[self.value]

    @classmethod
    def parse(cls, value: object) -> "Severity":
        text = str(value or "").strip().lower()
        mapping = {
            "info": cls.LOW, "informational": cls.LOW, "low": cls.LOW, "minor": cls.LOW,
            "medium": cls.MEDIUM, "moderate": cls.MEDIUM, "warning": cls.MEDIUM,
            "high": cls.HIGH, "major": cls.HIGH, "error": cls.HIGH,
            "critical": cls.CRITICAL, "severe": cls.CRITICAL, "blocker": cls.CRITICAL,
        }
        return mapping.get(text, cls.MEDIUM)


class Category(str, Enum):
    SECURITY = "Security"
    PERFORMANCE = "Performance"
    RELIABILITY = "Reliability"
    MAINTAINABILITY = "Maintainability"

    @classmethod
    def parse(cls, value: object) -> "Category":
        text = str(value or "").strip().lower()
        if text.startswith(("sec", "vuln")):
            return cls.SECURITY
        if text.startswith(("perf", "speed", "efficien")):
            return cls.PERFORMANCE
        if text.startswith(("maint", "style", "quality", "readab")):
            return cls.MAINTAINABILITY
        return cls.RELIABILITY


class SourceFile(BaseModel):
    path: str
    language: str
    content: str


class CodeChunk(BaseModel):
    file: str
    language: str
    start_line: int
    end_line: int
    content: str


class Finding(BaseModel):
    id: str
    file: str
    line: int
    rule_id: str
    title: str
    description: str = ""
    severity: Severity
    category: Category
    cwe: str | None = None
    snippet: str = ""
    recommendation: str = ""
    source: Literal["static", "llm"] = "static"


class Patch(BaseModel):
    file: str
    original: str
    patched: str
    diff: str
    addressed: list[str] = Field(default_factory=list)
    explanation: str = ""
    source: Literal["rules", "llm", "rules+llm"] = "rules"
    added: int = 0
    removed: int = 0


class Review(BaseModel):
    file: str
    confidence: float = Field(ge=0.0, le=1.0)
    verdict: Literal["approve", "revise", "reject"]
    checks: dict[str, bool] = Field(default_factory=dict)
    resolved: list[str] = Field(default_factory=list)
    unresolved: list[str] = Field(default_factory=list)
    new_findings: list[Finding] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class FileResult(BaseModel):
    file: str
    language: str
    findings: list[Finding] = Field(default_factory=list)
    patch: Patch | None = None
    review: Review | None = None
    iterations: int = 0
    notes: list[str] = Field(default_factory=list)
    error: str | None = None


class AuditReport(BaseModel):
    source: str
    mode: Literal["nebius", "offline"]
    models_used: list[str] = Field(default_factory=list)
    started_at: datetime
    duration_s: float = 0.0
    files_scanned: int = 0
    results: list[FileResult] = Field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        return [f for r in self.results for f in r.findings]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @computed_field  # type: ignore[prop-decorator]
    @property
    def patched_files(self) -> int:
        return sum(1 for r in self.results if r.patch is not None)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def average_confidence(self) -> float | None:
        scores = [r.review.confidence for r in self.results if r.review is not None]
        return round(sum(scores) / len(scores), 3) if scores else None
