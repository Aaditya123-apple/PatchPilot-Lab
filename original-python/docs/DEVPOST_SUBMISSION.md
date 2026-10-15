# Nebius-AgentX — Devpost submission

**Tagline:** Three AI agents that find security bugs, fix them, and check their own work, running NVIDIA Nemotron on Nebius AI Cloud.

## Inspiration

Every team we know has a backlog of scanner warnings nobody fixes. The tools are good at saying "line 42 is vulnerable" and bad at the part that costs time: writing a safe fix and convincing a reviewer it doesn't break anything. LLMs can write fixes, but a single pass gives you code you still have to check by hand. We wanted an agent team that does the checking too, so a developer only reviews patches that already passed verification.

## What it does

Nebius-AgentX takes a GitHub URL, a local folder or a pasted file and runs three collaborating agents:

1. **Scanner** combines 21 static rules (CWE-mapped) with Nemotron review of AST-aware code chunks, so it catches both known patterns and context-dependent issues.
2. **Refactor** applies deterministic AST-based fixes for common problems, then has Nemotron fix the rest, such as rewriting a string-built SQL query as a parameterized one.
3. **Reviewer** verifies every patch: the diff applies, the code parses, public functions survive, the original findings are gone and no new ones appear. A model review is blended in to produce a confidence score. Low-confidence patches go back to the Refactor agent with specific feedback.

The result is a dashboard with a severity breakdown and side-by-side diffs, a JSON report, a `git apply`-ready patch and, optionally, a branch and a GitHub pull request. It also runs as a CLI with a `--fail-on` gate for CI and as a FastAPI service.

## How we built it (Nebius Token Factory + NVIDIA ecosystem)

- **Inference:** the OpenAI Python SDK's `AsyncOpenAI`, pointed at the Nebius OpenAI-compatible endpoint. NVIDIA Llama-3.1-Nemotron-Ultra-253B is the primary model, with Nemotron Super 49B and Llama 3.3 70B as fallbacks.
- **Reliability layer:** retries with exponential backoff for rate limits and 5xx errors, automatic fallback when a model is unavailable, a shared concurrency cap, removal of Nemotron `<think>` traces, and tolerant JSON parsing with one self-repair request.
- **Orchestration:** an asyncio multi-agent loop. Files are audited concurrently, and each file loops Refactor → Reviewer until approval or a pass limit, keeping the best-scoring patch.
- **Grounding the model:** the Scanner sends numbered lines so findings point at exact locations. The Refactor agent starts from the rule-fixed file, and the Reviewer gets the automated check results alongside the diff.
- **Stack:** Python 3.11, FastAPI, Streamlit with Altair charts, Pydantic v2, GitPython, pytest.

## Challenges we ran into

- **Unparseable model output.** Reasoning traces, prose around JSON and truncated replies broke naive parsing, so we built a layered parser and a repair request.
- **Trusting a patch.** "The model says it's fixed" isn't evidence. We added a strict diff applier and re-run the static rules on the patched code, so "resolved" means the rule no longer fires on that line.
- **Precise edits.** Python AST positions are UTF-8 byte offsets, so the fixer maps them back to string offsets to avoid corrupting files with non-ASCII text.

## Accomplishments that we're proud of

- The agent loop corrects itself: unresolved findings and Reviewer notes go straight into the next Refactor pass.
- Everything still works offline. Without an API key, the rule engine, deterministic fixes and automated review still produce a scored patch, which makes the demo reliable.
- One pipeline serves three interfaces: dashboard, CLI and REST API.

## What we learned

Verification is the product. The model is very good at writing fixes, and its value multiplies once something objective checks those fixes. Open NVIDIA models on Nebius made it cheap to run multiple agents per file.

## What's next

- AST-level verification for JavaScript/TypeScript and Go.
- Running the project's own test suite against each patch in a sandbox.
- A GitHub App that comments on every pull request.

## 1-minute demo video script

| Time | On screen | Voice-over |
| --- | --- | --- |
| 0:00–0:08 | Title card, then the Streamlit dashboard | "Security scanners tell you what's broken. Nebius-AgentX fixes it and proves the fix works." |
| 0:08–0:18 | Click **Load vulnerable example**; scroll the code | "Here's a small Flask service with SQL injection, shell injection, a hardcoded password and unsafe YAML loading." |
| 0:18–0:30 | Click **Run Nebius Agent Audit**; status log streams Scanner, Refactor and Reviewer events | "Three agents run on NVIDIA Nemotron through Nebius AI Cloud. The Scanner finds issues, the Refactor agent writes patches and the Reviewer verifies them." |
| 0:30–0:42 | Severity chart and findings table | "Every finding has a severity, a CWE and a line number, from static rules and from the model." |
| 0:42–0:52 | Open the patch; side-by-side diff with the SQL query parameterized; checks row all green | "Here's the fix: a parameterized query. The Reviewer confirmed the diff applies, the code parses, the API is unchanged and the vulnerability is gone." |
| 0:52–1:00 | Terminal: `python -m src.cli <repo> --apply --pr`, then the GitHub PR | "Run it from the CLI and it opens the pull request for you. Nebius-AgentX: fixes you can trust." |
