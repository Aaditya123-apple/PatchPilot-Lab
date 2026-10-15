"""Loading code from paths, Git URLs or snippets, and turning approved patches into branches and PRs."""

from __future__ import annotations

import re
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import requests

from .models import AuditReport, SourceFile
from .scanner import detect_language, discover_files

_GIT_URL = re.compile(r"^(?:https?://|git@)\S+$")
_GITHUB = re.compile(r"github\.com[:/](?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?/?$")


def is_git_url(text: str) -> bool:
    text = text.strip()
    if not _GIT_URL.match(text):
        return False
    return text.endswith(".git") or any(h in text for h in ("github.com", "gitlab.com", "bitbucket.org"))


def guess_snippet_name(code: str) -> str:
    if re.search(r"^\s*(def |class |import |from \w+ import )", code, re.M):
        return "snippet.py"
    if re.search(r"\b(const|let|function)\b|=>", code):
        return "snippet.js"
    return "snippet.py"


@dataclass
class LoadedSource:
    label: str
    files: list[SourceFile]
    root: Path | None = None
    remote_url: str | None = None
    _tmp: tempfile.TemporaryDirectory | None = field(default=None, repr=False)

    def cleanup(self) -> None:
        if self._tmp is not None:
            self._tmp.cleanup()
            self._tmp = None


def load_source(source: str, *, filename: str | None = None, snippet: bool = False, shallow: bool = True) -> LoadedSource:
    """Resolve a local path, a Git URL or raw code into source files."""
    text = source.strip()
    if not snippet and is_git_url(text):
        try:
            from git import Repo
        except ImportError as exc:
            raise RuntimeError("Cloning needs git installed and on PATH.") from exc
        tmp = tempfile.TemporaryDirectory(prefix="agentx-")
        kwargs = {"depth": 1} if shallow else {}
        Repo.clone_from(text, tmp.name, **kwargs)
        return LoadedSource(label=text, files=discover_files(tmp.name), root=Path(tmp.name), remote_url=text, _tmp=tmp)
    if not snippet and "\n" not in text and len(text) < 1024:
        try:
            path = Path(text).expanduser()
            exists = path.exists()
        except (OSError, ValueError):
            exists = False
        if exists:
            root = path.resolve()
            files = discover_files(root)
            return LoadedSource(label=str(root), files=files, root=root.parent if root.is_file() else root)
        if not snippet and (text.startswith((".", "/", "~")) or re.match(r"^[A-Za-z]:[\\/]", text)):
            raise FileNotFoundError(f"Path not found: {text}")
    name = filename or guess_snippet_name(source)
    file = SourceFile(path=name, language=detect_language(name), content=source)
    return LoadedSource(label=f"snippet:{name}", files=[file])


def combined_patch(report: AuditReport) -> str:
    return "".join(r.patch.diff for r in report.results if r.patch and r.patch.diff)


def write_report_files(report: AuditReport, out_dir: str | Path) -> dict[str, Path]:
    out = Path(out_dir)
    (out / "patches").mkdir(parents=True, exist_ok=True)
    paths = {"report": out / "report.json", "patch": out / "agentx.patch"}
    paths["report"].write_text(report.model_dump_json(indent=2), encoding="utf-8")
    paths["patch"].write_text(combined_patch(report), encoding="utf-8")
    for r in report.results:
        if r.patch and r.patch.diff:
            target = out / "patches" / (r.file.replace("/", "__") + ".patch")
            target.write_text(r.patch.diff, encoding="utf-8")
    return paths


@dataclass
class ApplyResult:
    files: list[Path]
    branch: str | None = None
    base: str | None = None


def commit_message(report: AuditReport) -> str:
    counts = ", ".join(f"{v} {k.lower()}" for k, v in report.severity_counts.items() if v)
    lines = [f"AgentX: fix {report.total_findings} findings ({counts})", ""]
    for r in report.results:
        if r.patch and r.review:
            lines.append(f"- {r.file}: {len(r.patch.addressed)} fixed, confidence {r.review.confidence:.0%}")
    return "\n".join(lines)


def apply_patches(
    report: AuditReport,
    root: Path,
    *,
    branch: str = "agentx/security-fixes",
    commit: bool = True,
    verdicts: tuple[str, ...] = ("approve", "revise"),
) -> ApplyResult:
    """Write reviewed patches into the tree and, for Git checkouts, commit them on a new branch."""
    written: list[Path] = []
    for r in report.results:
        if r.patch and r.review and r.review.verdict in verdicts:
            target = root / r.file
            with open(target, "w", encoding="utf-8", newline="") as fh:
                fh.write(r.patch.patched)
            written.append(target)
    if not written or not commit:
        return ApplyResult(written)
    try:
        from git import InvalidGitRepositoryError, NoSuchPathError, Repo
    except ImportError:
        return ApplyResult(written)
    try:
        repo = Repo(root, search_parent_directories=True)
    except (InvalidGitRepositoryError, NoSuchPathError):
        return ApplyResult(written)
    try:
        base = repo.active_branch.name
    except TypeError:
        base = None
    if branch in [h.name for h in repo.heads]:
        branch = f"{branch}-{datetime.now():%Y%m%d%H%M%S}"
    repo.git.checkout("-b", branch)
    tree_root = Path(repo.working_tree_dir or root).resolve()
    repo.index.add([str(p.resolve().relative_to(tree_root)) for p in written])
    repo.index.commit(commit_message(report))
    return ApplyResult(written, branch, base)


def pull_request_body(report: AuditReport) -> str:
    rows = ["| File | Findings | Fixed | Confidence | Verdict |", "| --- | --- | --- | --- | --- |"]
    for r in report.results:
        if r.patch and r.review:
            rows.append(f"| `{r.file}` | {len(r.findings)} | {len(r.patch.addressed)} | {r.review.confidence:.0%} | {r.review.verdict} |")
    sev = " · ".join(f"{k}: {v}" for k, v in report.severity_counts.items())
    models = ", ".join(report.models_used) or "offline rule engine"
    return (
        "## Nebius-AgentX audit\n\n"
        f"Automated security and performance fixes from the Scanner, Refactor and Reviewer agents.\n\n"
        f"**Severity:** {sev}  \n**Models:** {models}\n\n" + "\n".join(rows) +
        "\n\nEach patch passed diff, syntax and API checks before this PR was opened. Please review before merging."
    )


def open_pull_request(
    root: Path, remote_url: str, branch: str, base: str | None, report: AuditReport, token: str | None
) -> str:
    """Push `branch` to GitHub and open a pull request. Returns the PR URL."""
    if not token:
        raise RuntimeError("Set GITHUB_TOKEN to open pull requests.")
    m = _GITHUB.search(remote_url)
    if not m:
        raise RuntimeError(f"Only GitHub remotes are supported for PRs: {remote_url}")
    owner, name = m.group("owner"), m.group("repo")
    from git import GitCommandError, Repo

    repo = Repo(root, search_parent_directories=True)
    try:
        repo.git.push(f"https://x-access-token:{token}@github.com/{owner}/{name}.git", f"{branch}:{branch}")
    except GitCommandError as exc:
        raise RuntimeError(str(exc).replace(token, "***")) from None
    resp = requests.post(
        f"https://api.github.com/repos/{owner}/{name}/pulls",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        json={
            "title": f"AgentX: fix {report.total_findings} security and performance findings",
            "head": branch,
            "base": base or "main",
            "body": pull_request_body(report),
        },
        timeout=30,
    )
    if resp.status_code >= 400:
        raise RuntimeError(f"GitHub refused the pull request ({resp.status_code}): {resp.text[:300]}")
    return resp.json()["html_url"]
