"""Unified and side-by-side diffs, a strict diff applier used for verification, and HTML rendering."""

from __future__ import annotations

import difflib
import html
import re
from dataclasses import dataclass

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def _lines(text: str) -> list[str]:
    lines = text.splitlines(keepends=True)
    if lines and not lines[-1].endswith(("\n", "\r")):
        lines[-1] += "\n"
    return lines


def unified_diff(original: str, patched: str, path: str = "file", context: int = 3) -> str:
    """A git-style unified diff. Returns an empty string when the texts are identical."""
    if original == patched:
        return ""
    return "".join(
        difflib.unified_diff(_lines(original), _lines(patched), fromfile=f"a/{path}", tofile=f"b/{path}", n=context)
    )


def apply_unified_diff(original: str, diff: str) -> str:
    """Apply a single-file unified diff, raising ValueError if any context line does not match."""
    src = _lines(original)
    out: list[str] = []
    i = 0
    lines = diff.splitlines(keepends=True)
    k = 0
    while k < len(lines):
        m = _HUNK.match(lines[k])
        if not m:
            k += 1
            continue
        start = int(m.group(1))
        count = int(m.group(2)) if m.group(2) is not None else 1
        target = start - 1 if count > 0 else start
        if target < i:
            raise ValueError("Overlapping hunks")
        out.extend(src[i:target])
        i = target
        k += 1
        while k < len(lines) and not lines[k].startswith("@@"):
            line = lines[k]
            tag, body = line[:1], line[1:]
            if tag in (" ", "-"):
                if i >= len(src) or src[i].rstrip("\r\n") != body.rstrip("\r\n"):
                    raise ValueError(f"Context mismatch at original line {i + 1}")
                if tag == " ":
                    out.append(src[i])
                i += 1
            elif tag == "+":
                out.append(body if body.endswith("\n") else body + "\n")
            elif tag == "\\" or line.strip() == "":
                pass
            else:
                raise ValueError(f"Unexpected diff line: {line!r}")
            k += 1
    out.extend(src[i:])
    return "".join(out)


@dataclass
class DiffRow:
    kind: str  # equal | replace | delete | insert | skip
    left_no: int | None
    left: str
    right_no: int | None
    right: str


def side_by_side(original: str, patched: str) -> list[DiffRow]:
    a, b = original.splitlines(), patched.splitlines()
    rows: list[DiffRow] = []
    matcher = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for x in range(i2 - i1):
                rows.append(DiffRow("equal", i1 + x + 1, a[i1 + x], j1 + x + 1, b[j1 + x]))
            continue
        for x in range(max(i2 - i1, j2 - j1)):
            li = i1 + x if i1 + x < i2 else None
            rj = j1 + x if j1 + x < j2 else None
            kind = "replace" if li is not None and rj is not None else ("delete" if li is not None else "insert")
            rows.append(DiffRow(
                kind,
                li + 1 if li is not None else None,
                a[li] if li is not None else "",
                rj + 1 if rj is not None else None,
                b[rj] if rj is not None else "",
            ))
    return rows


def collapse_rows(rows: list[DiffRow], context: int = 3) -> list[DiffRow]:
    """Keep changed rows plus `context` rows around them; replace long equal runs with a skip row."""
    changed = [i for i, r in enumerate(rows) if r.kind != "equal"]
    if not changed:
        return rows
    keep = set()
    for i in changed:
        keep.update(range(max(0, i - context), min(len(rows), i + context + 1)))
    out: list[DiffRow] = []
    skipped = 0
    for i, row in enumerate(rows):
        if i in keep:
            if skipped:
                out.append(DiffRow("skip", None, f"{skipped} unchanged lines", None, ""))
                skipped = 0
            out.append(row)
        else:
            skipped += 1
    if skipped:
        out.append(DiffRow("skip", None, f"{skipped} unchanged lines", None, ""))
    return out


def diff_stats(original: str, patched: str) -> dict[str, float]:
    a, b = original.splitlines(), patched.splitlines()
    added = removed = 0
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(a=a, b=b, autojunk=False).get_opcodes():
        if tag in ("replace", "delete"):
            removed += i2 - i1
        if tag in ("replace", "insert"):
            added += j2 - j1
    return {"added": added, "removed": removed, "changed_ratio": round((added + removed) / max(1, len(a) + len(b)), 4)}


def render_side_by_side_html(rows: list[DiffRow]) -> str:
    """Render rows as a two-column HTML table (styles live in the Streamlit app)."""
    parts = ['<div class="diff-wrap"><table class="diff"><thead><tr>'
             '<th class="no"></th><th>Original</th><th class="no"></th><th>AgentX patch</th></tr></thead><tbody>']
    for r in rows:
        if r.kind == "skip":
            parts.append(f'<tr class="skip"><td colspan="4">{html.escape(r.left)}</td></tr>')
            continue
        left_cls = "del" if r.kind in ("replace", "delete") else ""
        right_cls = "add" if r.kind in ("replace", "insert") else ""
        parts.append(
            "<tr>"
            f'<td class="no">{r.left_no or ""}</td><td class="code {left_cls}">{html.escape(r.left) or "&nbsp;"}</td>'
            f'<td class="no">{r.right_no or ""}</td><td class="code {right_cls}">{html.escape(r.right) or "&nbsp;"}</td>'
            "</tr>"
        )
    parts.append("</tbody></table></div>")
    return "".join(parts)
