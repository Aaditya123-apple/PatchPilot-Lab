"""Nebius-AgentX Streamlit console. Run with: streamlit run app/main.py"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import altair as alt  # noqa: E402
import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from src.config import get_settings  # noqa: E402
from src.diffing import collapse_rows, render_side_by_side_html, side_by_side  # noqa: E402
from src.models import AuditReport, FileResult  # noqa: E402
from src.orchestrator import AuditOrchestrator  # noqa: E402
from src.repo import combined_patch  # noqa: E402

EXAMPLE = ROOT / "examples" / "vulnerable_app.py"
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
SEVERITY_COLORS = {"Critical": "#ff4d5e", "High": "#ff8a3d", "Medium": "#f5c04a", "Low": "#6fb3ff"}

st.set_page_config(page_title="Nebius-AgentX", layout="wide")

st.markdown(
    """
<style>
:root { --nv-green:#76b900; --panel:#151b23; --line:#263040; --muted:#8b98a9; }
.block-container { padding-top: 2rem; max-width: 1400px; }
.hero h1 { font-size: 2.4rem; margin: 0; letter-spacing: -0.02em; }
.hero h1 span { color: var(--nv-green); }
.hero p { color: var(--muted); margin: .25rem 0 0; font-size: 1.05rem; }
.pill { display:inline-block; padding:2px 10px; border-radius:999px; font-size:.78rem; font-weight:600;
        border:1px solid var(--line); margin-right:6px; }
.pill.ok { color:#b8f07a; border-color:#3d5c12; background:#18240a; }
.pill.off { color:#f5c04a; border-color:#5c4a12; background:#241d0a; }
.check { display:inline-block; margin:2px 6px 2px 0; padding:2px 8px; border-radius:6px; font-size:.8rem;
         background:var(--panel); border:1px solid var(--line); }
.check.pass { color:#b8f07a; } .check.fail { color:#ff8a8a; }
.diff-wrap { max-height: 520px; overflow:auto; border:1px solid var(--line); border-radius:8px; }
table.diff { width:100%; border-collapse:collapse; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
             font-size:12.5px; table-layout:fixed; }
table.diff th { position:sticky; top:0; background:#10151c; color:var(--muted); text-align:left; padding:6px 8px;
                font-weight:600; border-bottom:1px solid var(--line); }
table.diff td { padding:1px 8px; vertical-align:top; white-space:pre-wrap; word-break:break-all; }
table.diff td.no, table.diff th.no { width:44px; color:#5d6b7c; text-align:right; user-select:none; }
table.diff td.del { background:rgba(255,77,94,.14); }
table.diff td.add { background:rgba(118,185,0,.16); }
table.diff tr.skip td { color:var(--muted); background:#10151c; text-align:center; font-style:italic; padding:4px; }
</style>
""",
    unsafe_allow_html=True,
)

settings = get_settings()


def load_example() -> None:
    st.session_state["code"] = EXAMPLE.read_text(encoding="utf-8")
    st.session_state["filename"] = "vulnerable_app.py"
    st.session_state["input_mode"] = "Paste code"


# ---------------------------------------------------------------- sidebar
with st.sidebar:
    st.markdown("### Inference")
    if settings.offline:
        st.markdown('<span class="pill off">Offline rule engine</span>', unsafe_allow_html=True)
        st.caption("Set NEBIUS_API_KEY in .env to add NVIDIA model reasoning on Nebius AI Cloud.")
    else:
        st.markdown('<span class="pill ok">Nebius AI Cloud connected</span>', unsafe_allow_html=True)
        st.caption(f"Endpoint: {settings.base_url}")
    st.markdown("**Model chain**")
    for i, m in enumerate(settings.model_chain):
        st.caption(f"{'Primary' if i == 0 else f'Fallback {i}'}: `{m}`")
    st.divider()
    st.markdown("### Agent loop")
    use_llm = st.toggle("Use Nebius models", value=not settings.offline, disabled=settings.offline)
    iterations = st.slider("Refactor/Review passes", 1, 4, 2)
    threshold = st.slider("Approval confidence", 0.5, 0.95, 0.8, 0.05)

# ---------------------------------------------------------------- input
st.markdown(
    '<div class="hero"><h1>Nebius-<span>AgentX</span></h1>'
    "<p>Three agents scan your code, write patches and verify them, on NVIDIA models served by Nebius AI Cloud.</p></div>",
    unsafe_allow_html=True,
)
st.write("")

mode = st.radio("Audit from", ["Repository or path", "Paste code"], horizontal=True, key="input_mode")
if mode == "Repository or path":
    source = st.text_input(
        "Local path or Git URL",
        placeholder="https://github.com/owner/repo  or  C:\\projects\\my-service",
        key="source",
    )
    filename = None
else:
    cols = st.columns([3, 1])
    st.session_state.setdefault("filename", "snippet.py")
    filename = cols[0].text_input("File name", key="filename")
    cols[1].write("")
    cols[1].button("Load vulnerable example", on_click=load_example, use_container_width=True)
    source = st.text_area("Code", height=280, key="code", placeholder="Paste a file to audit")

run = st.button("Run Nebius Agent Audit", type="primary", use_container_width=True)

EVENT_TEXT = {
    "start": lambda d: f"Auditing {d['files']} file(s) in **{d['mode']}** mode",
    "scan_done": lambda d: f"Scanner · `{d['file']}` · {d['findings']} finding(s)",
    "refactor": lambda d: f"Refactor · `{d['file']}` · pass {d['iteration']}",
    "review": lambda d: f"Reviewer · `{d['file']}` · confidence {d['confidence']:.0%} → {d['verdict']}",
    "error": lambda d: f"Error · `{d['file']}` · {d['error']}",
}

if run:
    if not (source or "").strip():
        st.warning("Enter a path, a Git URL or some code first.")
    else:
        with st.status("Agents working…", expanded=True) as status:
            def on_progress(event: str, data: dict) -> None:
                fmt = EVENT_TEXT.get(event)
                if fmt:
                    status.write(fmt(data))

            orchestrator = AuditOrchestrator(
                max_iterations=iterations, approve_threshold=threshold, use_llm=use_llm, progress=on_progress
            )
            try:
                report = asyncio.run(orchestrator.audit(source, filename=filename, snippet=mode == "Paste code"))
            except Exception as exc:  # show any failure in the UI instead of a traceback
                status.update(label="Audit failed", state="error")
                st.error(f"{type(exc).__name__}: {exc}")
                st.stop()
            status.update(label=f"Audit complete in {report.duration_s:.1f}s", state="complete", expanded=False)
        st.session_state["report"] = report


# ---------------------------------------------------------------- results
def checks_html(result: FileResult) -> str:
    if not result.review:
        return ""
    names = {
        "diff_applies": "Diff applies", "syntax_valid": "Syntax valid", "public_api_preserved": "API preserved",
        "minimal_change": "Minimal change", "no_new_issues": "No new issues", "findings_resolved": "All findings resolved",
    }
    return "".join(
        f'<span class="check {"pass" if ok else "fail"}">{"✓" if ok else "✗"} {names.get(k, k)}</span>'
        for k, ok in result.review.checks.items()
    )


def render(report: AuditReport) -> None:
    counts = report.severity_counts
    c = st.columns(5)
    c[0].metric("Files scanned", report.files_scanned)
    c[1].metric("Findings", report.total_findings)
    c[2].metric("Critical + High", counts["Critical"] + counts["High"])
    c[3].metric("Files patched", report.patched_files)
    c[4].metric("Avg. confidence", f"{report.average_confidence:.0%}" if report.average_confidence is not None else "—")
    st.caption(
        f"Mode: {report.mode} · Models: {', '.join(report.models_used) or 'rule engine only'} · "
        f"Source: {report.source}"
    )

    if not report.findings:
        st.success("No findings. The code passed every rule and model check.")
        return

    df = pd.DataFrame(
        [
            {"Severity": f.severity.value, "Category": f.category.value, "File": f.file, "Line": f.line,
             "Rule": f.rule_id, "Title": f.title, "CWE": f.cwe or "", "Detected by": f.source}
            for f in report.findings
        ]
    )
    left, right = st.columns([3, 2])
    with left:
        st.markdown("#### Severity distribution")
        sev = pd.DataFrame({"Severity": SEVERITY_ORDER, "Findings": [counts[s] for s in SEVERITY_ORDER]})
        chart = (
            alt.Chart(sev)
            .mark_bar(cornerRadiusTopRight=4, cornerRadiusBottomRight=4)
            .encode(
                y=alt.Y("Severity:N", sort=SEVERITY_ORDER, title=None),
                x=alt.X("Findings:Q", title=None, axis=alt.Axis(tickMinStep=1)),
                color=alt.Color("Severity:N", scale=alt.Scale(domain=list(SEVERITY_COLORS), range=list(SEVERITY_COLORS.values())), legend=None),
                tooltip=["Severity", "Findings"],
            )
            .properties(height=220)
        )
        st.altair_chart(chart, use_container_width=True)
    with right:
        st.markdown("#### By category")
        cat = df.groupby("Category").size().reset_index(name="Findings")
        donut = (
            alt.Chart(cat)
            .mark_arc(innerRadius=55)
            .encode(
                theta="Findings:Q",
                color=alt.Color("Category:N", scale=alt.Scale(scheme="tableau10"), legend=alt.Legend(orient="right")),
                tooltip=["Category", "Findings"],
            )
            .properties(height=220)
        )
        st.altair_chart(donut, use_container_width=True)

    st.markdown("#### Findings")
    df["_rank"] = df["Severity"].map({s: i for i, s in enumerate(SEVERITY_ORDER)})
    st.dataframe(df.sort_values(["_rank", "File", "Line"]).drop(columns="_rank"), hide_index=True, use_container_width=True)

    st.markdown("#### Patches")
    for result in report.results:
        if not result.findings:
            continue
        conf = f"{result.review.confidence:.0%} · {result.review.verdict}" if result.review else "no patch"
        with st.expander(f"{result.file} — {len(result.findings)} finding(s) — {conf}", expanded=result is report.results[0]):
            if result.error:
                st.error(result.error)
            if result.patch:
                st.markdown(checks_html(result), unsafe_allow_html=True)
                if result.patch.explanation:
                    st.caption(result.patch.explanation)
                rows = collapse_rows(side_by_side(result.patch.original, result.patch.patched), context=3)
                st.markdown(render_side_by_side_html(rows), unsafe_allow_html=True)
                st.download_button(
                    "Download patch", result.patch.diff, file_name=f"{Path(result.file).name}.patch",
                    key=f"dl-{result.file}",
                )
            else:
                st.info("No automatic patch for this file. See the recommendations in the findings table.")
            if result.review and result.review.notes:
                st.markdown("**Reviewer notes**")
                for note in result.review.notes:
                    st.markdown(f"- {note}")
            for note in result.notes:
                st.caption(note)

    st.divider()
    d1, d2 = st.columns(2)
    d1.download_button("Download full report (JSON)", report.model_dump_json(indent=2), "agentx-report.json",
                       use_container_width=True)
    d2.download_button("Download combined patch", combined_patch(report) or "", "agentx.patch",
                       use_container_width=True, disabled=not report.patched_files)


if "report" in st.session_state:
    render(st.session_state["report"])
