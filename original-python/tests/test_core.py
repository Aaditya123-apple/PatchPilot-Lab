# Credential-like strings in this test file are fictional scanner fixtures, never usable secrets.
"""Core tests: Nebius client parsing and fallbacks, chunking, static rules, fixes, diffs and the agent loop."""

from __future__ import annotations

import ast
import asyncio
import json
import re
from types import SimpleNamespace

import httpx
import openai
import pytest

from src.agent import RefactorAgent, ReviewerAgent, ScannerAgent
from src.config import Settings
from src.diffing import apply_unified_diff, collapse_rows, diff_stats, side_by_side, unified_diff
from src.fixers import apply_rule_fixes
from src.models import Severity, SourceFile
from src.nebius_client import ChatResult, NebiusClient, NebiusError, extract_code_blocks, parse_json_payload
from src.orchestrator import AuditOrchestrator
from src.repo import load_source
from src.scanner import chunk_source, discover_files, static_scan

VULN = 'import sqlite3\nimport subprocess\nimport yaml\n\nAPI_KEY = "NOT_A_REAL_TEST_CREDENTIAL_123"\n\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n\n\ndef load(text):\n    return yaml.load(text)\n\n\ndef find_user(conn, name):\n    return conn.execute(f"SELECT * FROM users WHERE name = \'{name}\'").fetchall()\n'

SQL_BAD = "conn.execute(f\"SELECT * FROM users WHERE name = '{name}'\").fetchall()"
SQL_GOOD = 'conn.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()'


# ---------------------------------------------------------------- helpers

def completion(content: str, model: str = "nvidia/primary") -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content))],
        model=model,
        usage=SimpleNamespace(prompt_tokens=12, completion_tokens=7),
    )


def api_error(cls: type[openai.APIStatusError], status: int) -> openai.APIStatusError:
    request = httpx.Request("POST", "https://api.example.test/v1/chat/completions")
    return cls("boom", response=httpx.Response(status, request=request), body=None)


class FakeCompletions:
    def __init__(self, outcomes: list) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[dict] = []

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def fake_client(outcomes: list, **settings) -> tuple[NebiusClient, FakeCompletions]:
    completions = FakeCompletions(outcomes)
    raw = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    cfg = Settings(api_key="test-key", model="nvidia/primary", fallback_models=("meta/fallback",), **settings)

    async def no_sleep(_: float) -> None:
        return None

    return NebiusClient(cfg, client=raw, sleep=no_sleep), completions


def py(content: str, path: str = "app.py") -> SourceFile:
    return SourceFile(path=path, language="python", content=content)


# ---------------------------------------------------------------- Nebius client

def test_parse_json_payload_handles_reasoning_fences_and_prose():
    assert parse_json_payload('{"a": 1}') == {"a": 1}
    assert parse_json_payload('<think>let me think {"x": 0}</think>\n```json\n{"a": [1, 2]}\n```') == {"a": [1, 2]}
    assert parse_json_payload('Here you go: {"findings": [{"line": 3}]} hope it helps') == {"findings": [{"line": 3}]}
    with pytest.raises(ValueError):
        parse_json_payload("no json here")


def test_chat_parses_mocked_nebius_response_and_strips_reasoning():
    client, completions = fake_client([completion('<think>internal</think>{"ok": true}')])
    result = asyncio.run(client.chat([{"role": "user", "content": "hi"}], json_mode=True))
    assert result.content == '{"ok": true}'
    assert result.model == "nvidia/primary"
    assert (result.prompt_tokens, result.completion_tokens) == (12, 7)
    assert completions.calls[0]["response_format"] == {"type": "json_object"}
    assert client.models_used == ["nvidia/primary"]


def test_chat_falls_back_to_next_model_when_model_missing():
    client, completions = fake_client([api_error(openai.NotFoundError, 404), completion("hello", model="meta/fallback")])
    result = asyncio.run(client.chat([{"role": "user", "content": "hi"}]))
    assert result.content == "hello"
    assert [c["model"] for c in completions.calls] == ["nvidia/primary", "meta/fallback"]


def test_chat_retries_rate_limits_then_succeeds():
    client, completions = fake_client(
        [api_error(openai.RateLimitError, 429), api_error(openai.RateLimitError, 429), completion("done")], max_retries=3
    )
    assert asyncio.run(client.chat([{"role": "user", "content": "hi"}])).content == "done"
    assert len(completions.calls) == 3


def test_chat_drops_json_mode_when_model_rejects_it():
    client, completions = fake_client([api_error(openai.BadRequestError, 400), completion('{"a": 1}')])
    asyncio.run(client.chat([{"role": "user", "content": "hi"}], json_mode=True))
    assert "response_format" in completions.calls[0] and "response_format" not in completions.calls[1]


def test_chat_raises_when_every_model_fails():
    client, _ = fake_client([api_error(openai.NotFoundError, 404), api_error(openai.NotFoundError, 404)])
    with pytest.raises(NebiusError):
        asyncio.run(client.chat([{"role": "user", "content": "hi"}]))


def test_offline_client_is_unavailable():
    client = NebiusClient(Settings(api_key=None))
    assert not client.available
    with pytest.raises(NebiusError):
        asyncio.run(client.chat([{"role": "user", "content": "hi"}]))


def test_stream_yields_deltas():
    async def chunks():
        for piece in ["Hel", None, "lo"]:
            yield SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content=piece))])

    client, _ = fake_client([chunks()])

    async def collect() -> str:
        return "".join([d async for d in client.stream([{"role": "user", "content": "hi"}])])

    assert asyncio.run(collect()) == "Hello"


# ---------------------------------------------------------------- chunking & discovery

def test_python_chunks_cover_every_line_and_respect_limit():
    funcs = "\n\n".join(f"def f{i}(x):\n" + "\n".join(f"    x += {j}" for j in range(8)) + "\n    return x" for i in range(30))
    file = py("import os\n\n" + funcs + "\n")
    chunks = chunk_source(file, max_lines=40)
    n = len(file.content.splitlines())
    covered = set()
    for c in chunks:
        assert c.end_line - c.start_line + 1 <= 40
        covered.update(range(c.start_line, c.end_line + 1))
        assert c.content == "\n".join(file.content.splitlines()[c.start_line - 1 : c.end_line])
    assert covered == set(range(1, n + 1))
    starts = {c.start_line for c in chunks}
    def_lines = {i for i, line in enumerate(file.content.splitlines(), 1) if line.startswith("def ")}
    assert starts - {1} <= def_lines  # chunks begin on function boundaries


def test_oversized_function_is_split_and_generic_windows_overlap():
    big = "def big():\n" + "\n".join(f"    a = {i}" for i in range(100)) + "\n"
    chunks = chunk_source(py(big), max_lines=30)
    assert all(c.end_line - c.start_line + 1 <= 30 for c in chunks)
    assert chunks[-1].end_line == 101
    js = SourceFile(path="a.js", language="javascript", content="\n".join(f"let v{i} = {i};" for i in range(50)))
    win = chunk_source(js, max_lines=20, overlap=5)
    assert [(c.start_line, c.end_line) for c in win] == [(1, 20), (16, 35), (31, 50)]
    assert chunk_source(py(""), max_lines=10) == []


def test_discover_files_skips_vendored_and_hidden_dirs(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n")
    (tmp_path / "src" / "notes.txt").write_text("ignore me")
    for d in ("node_modules", ".git", "__pycache__"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "skip.py").write_text("x = 2\n")
    files = discover_files(tmp_path)
    assert [f.path for f in files] == ["src/app.py"]


# ---------------------------------------------------------------- static rules & fixes

def test_static_scan_flags_expected_rules():
    rules = {(f.rule_id, f.line) for f in static_scan(py(VULN))}
    assert {("PY008", 5), ("PY002", 9), ("PY004", 13), ("PY007", 17)} <= rules
    sql = next(f for f in static_scan(py(VULN)) if f.rule_id == "PY007")
    assert sql.severity is Severity.CRITICAL and sql.cwe == "CWE-89"


def test_static_scan_ignores_safe_code():
    safe = 'import yaml\n\ndef load(t):\n    return yaml.safe_load(t)\n\nPASSWORD = ""\n'
    assert static_scan(py(safe)) == []


def test_rule_fixes_produce_valid_code_and_clear_findings():
    findings = static_scan(py(VULN))
    fix = apply_rule_fixes(VULN, findings)
    ast.parse(fix.code)
    assert "yaml.safe_load(text)" in fix.code
    assert "subprocess.run(shlex.split(cmd), shell=False)" in fix.code
    assert 'os.environ.get("API_KEY", "")' in fix.code
    assert "import os" in fix.code and "import shlex" in fix.code
    remaining = {f.rule_id for f in static_scan(py(fix.code))}
    assert remaining == {"PY007"}  # SQL injection needs the model


def test_mutable_default_and_bare_except_fixes():
    code = 'def add(item, tags=[]):\n    """Add a tag."""\n    tags.append(item)\n    try:\n        return tags\n    except:\n        return None\n'
    fix = apply_rule_fixes(code, static_scan(py(code)))
    assert "def add(item, tags=None):" in fix.code
    assert "    if tags is None:\n        tags = []\n" in fix.code
    assert "except Exception:" in fix.code
    ns: dict = {}
    exec(compile(fix.code, "t", "exec"), ns)  # noqa: S102 - executing our own fixed test code
    assert ns["add"]("a") == ["a"] and ns["add"]("b") == ["b"]


# ---------------------------------------------------------------- diffs

def test_unified_diff_round_trips_and_handles_identical_input():
    a = "one\ntwo\nthree\nfour\n"
    b = "one\n2\nthree\nfour\nfive\n"
    diff = unified_diff(a, b, "x.py")
    assert diff.startswith("--- a/x.py\n+++ b/x.py\n")
    assert "-two\n" in diff and "+2\n" in diff and "+five\n" in diff
    assert apply_unified_diff(a, diff) == b
    assert unified_diff(a, a) == ""


def test_apply_diff_rejects_mismatched_context():
    diff = unified_diff("a\nb\nc\n", "a\nB\nc\n")
    with pytest.raises(ValueError):
        apply_unified_diff("a\nX\nc\n", diff)


def test_side_by_side_rows_reconstruct_both_sides():
    a = "keep\nold\nsame\ngone\n"
    b = "keep\nnew\nsame\nadded\nmore\n"
    rows = side_by_side(a, b)
    assert [r.left for r in rows if r.left_no] == a.splitlines()
    assert [r.right for r in rows if r.right_no] == b.splitlines()
    assert {r.kind for r in rows} >= {"equal", "replace", "insert"}
    stats = diff_stats(a, b)
    assert (stats["added"], stats["removed"]) == (3, 2)


def test_collapse_rows_skips_long_unchanged_runs():
    a = "\n".join(str(i) for i in range(50))
    b = a.replace("25", "twenty-five")
    rows = collapse_rows(side_by_side(a, b), context=2)
    assert sum(r.kind == "skip" for r in rows) == 2
    assert len(rows) == 2 + 5


# ---------------------------------------------------------------- agents & orchestration

class ScriptedLLM:
    """Stands in for NebiusClient and answers each agent the way a Nemotron model would."""

    available = True

    def __init__(self) -> None:
        self.models_used = ["nvidia/test-nemotron"]
        self.calls: list[str] = []

    def reply(self, messages) -> str:
        system, user = messages[0]["content"], messages[-1]["content"]
        if "Scanner agent" in system:
            self.calls.append("scanner")
            return '{"findings": [{"line": 13, "title": "Config loaded without validation", "severity": "low", "category": "reliability"}]}'
        if "Refactor agent" in system:
            self.calls.append("refactor")
            code = next(body for lang, body in extract_code_blocks(user) if lang == "python")
            fixed = code.replace(SQL_BAD, SQL_GOOD)
            ids = json.dumps(re.findall(r"\[([^\]\s]+@[^\]\s]+)\]", user))
            return f"```python\n{fixed}```\n```json\n{{\"addressed\": {ids}, \"explanation\": \"Parameterized the SQL query.\"}}\n```"
        self.calls.append("reviewer")
        return '{"confidence": 0.95, "verdict": "approve", "unresolved": [], "notes": ["Looks good."]}'

    async def chat(self, messages, **kwargs) -> ChatResult:
        return ChatResult(content=self.reply(messages), model="nvidia/test-nemotron", latency_s=0.0)

    async def chat_json(self, messages, **kwargs):
        return parse_json_payload((await self.chat(messages)).content)


def test_scanner_merges_model_findings_with_static_rules():
    findings, notes = asyncio.run(ScannerAgent(ScriptedLLM()).run(py(VULN)))
    assert not notes
    llm_found = [f for f in findings if f.source == "llm"]
    assert len(llm_found) == 1 and llm_found[0].line == 13 and llm_found[0].severity is Severity.LOW
    assert llm_found[0].snippet == "return yaml.load(text)"
    assert any(f.rule_id == "PY007" for f in findings)
    assert findings[0].severity is Severity.CRITICAL  # sorted most severe first


def test_full_agent_loop_with_mocked_nebius_model():
    llm = ScriptedLLM()
    report = asyncio.run(AuditOrchestrator(llm, max_iterations=2).audit(VULN, filename="users.py", snippet=True))
    assert report.mode == "nebius" and report.models_used == ["nvidia/test-nemotron"]
    result = report.results[0]
    assert result.patch is not None and result.patch.source == "rules+llm"
    assert SQL_GOOD in result.patch.patched
    assert result.review.checks["diff_applies"] and result.review.checks["syntax_valid"]
    assert result.review.checks["findings_resolved"]
    assert result.review.verdict == "approve" and result.review.confidence >= 0.8
    assert llm.calls.count("refactor") == 1


def test_offline_audit_still_patches_and_scores():
    report = asyncio.run(AuditOrchestrator(NebiusClient(Settings(api_key=None)), max_iterations=3).audit(VULN, snippet=True))
    assert report.mode == "offline"
    result = report.results[0]
    assert report.severity_counts["Critical"] == 1
    assert result.patch is not None and result.patch.source == "rules"
    assert result.review is not None and 0 < result.review.confidence < 1
    assert any(fid.startswith("PY007") for fid in result.review.unresolved)
    assert result.review.verdict != "approve"  # an open Critical finding blocks approval
    assert result.iterations == 1


def test_reviewer_rejects_broken_patch():
    file = py(VULN)
    findings = static_scan(file)
    patch, _ = asyncio.run(RefactorAgent().run(file, findings))
    broken = patch.model_copy(update={"patched": patch.patched + "\ndef oops(:\n"})
    review = asyncio.run(ReviewerAgent().run(file, findings, broken))
    assert review.confidence == 0.0 and review.verdict == "reject"
    assert not review.checks["syntax_valid"]


def test_load_source_reads_paths_and_snippets(tmp_path):
    (tmp_path / "svc.py").write_text("print('hi')\n")
    loaded = load_source(str(tmp_path))
    assert [f.path for f in loaded.files] == ["svc.py"] and loaded.root == tmp_path.resolve()
    snippet = load_source("const a = 1;", snippet=True)
    assert snippet.files[0].language == "javascript"


def test_api_audit_endpoint():
    from fastapi.testclient import TestClient

    from src.api import app

    client = TestClient(app)
    assert client.get("/health").json()["status"] == "ok"
    resp = client.post("/audit", json={"code": VULN, "filename": "users.py", "use_llm": False})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_findings"] >= 4 and body["severity_counts"]["Critical"] == 1
    assert client.post("/audit", json={}).status_code == 422
