# PatchPilot

[![License: MIT](https://img.shields.io/badge/License-MIT-orange.svg)](LICENSE)

A code review workbench combining local syntax/security checks with NVIDIA Nemotron inference on **Nebius Token Factory**. The AI Scanner explains likely defects; the AI Refactor proposes a conservative replacement; the browser checks supported Python/JavaScript proposal syntax before it can be loaded. It never executes submitted or generated code.

**Track:** Coding and Agentic Engineering.
**Hosted application:** https://patchpilot-workbench.higgsfield.app/
**Public judging repository:** https://github.com/Aaditya123-apple/PatchPilot-Lab

## What runs where

- **Nebius Token Factory:** real chat-completion inference for Scanner and, when findings exist, Refactor. Default endpoint `https://api.tokenfactory.us-central1.nebius.com/v1/`; default NVIDIA model `nvidia/nemotron-3-super-120b-a12b`. An owner may configure another NVIDIA Nemotron model available in their Token Factory project. The gateway rejects non-NVIDIA/non-Nemotron configurations. No unrelated-provider fallback is used.
- **Browser:** Python AST/compile-context checks, Pyflakes, the original security rules, Acorn JavaScript checks, and syntax/static review of AI proposals. User code is treated as data.
- **Application server:** secret handling, input/origin validation, output validation, bounded inference calls and quota enforcement. Hosting the UI outside Nebius does not move inference off Token Factory.
- **Cloudflare D1 on the hosted deployment:** quota counters only, not a Nebius database, user-source database or scan history. No prompts, submitted code, responses or API keys are stored by application code. The local server uses process-memory counters and is for development/testing only.

The optional AI step explicitly asks before sending the snippet and local diagnostics to Nebius. Local checks send no code to a server. Nebius's own service data handling is governed by its policies. Full-project browsing and ZIP downloads are removed from the product UI; the repository remains public because the challenge requires it. Browser-delivered code is inspectable.

## Run the complete browser + AI application locally

Use Node.js 22 or newer. No npm dependencies are needed for this server.

1. Clone this repository and open its folder.
2. Copy `.env.example` to `.env` (`Copy-Item .env.example .env` in PowerShell, or `cp .env.example .env` on macOS/Linux).
3. Set `NEBIUS_API_KEY` in your local `.env` using a funded Token Factory project. Never commit it. Confirm the model/region in your Token Factory catalog; set `NEBIUS_BASE_URL` and `NVIDIA_MODEL_NAME` if needed.
4. Run `npm start` and open `http://127.0.0.1:3000`.
5. Paste a short Python/JavaScript snippet, run local checks, enable the Nebius consent checkbox and select **Review with Nemotron**.
6. Review findings, actual inference evidence and the candidate's syntax result. Download the AI report or load a syntax-valid proposal into the editor. Run your own project tests before use.

Without a key, local checks work and AI review explicitly reports that owner setup is required. The application never presents local rules as a successful Nebius inference. GitHub Pages can only serve the local static workbench; use the hosted application or `npm start` for the server-backed AI feature.

## Hosted setup

The platform-specific Higgsfield/TanStack integration overlay is under `hosting/`; it assumes the host-provided TanStack scaffold. The complete standalone reproduction path is the Node server above, which does not require that scaffold. The gateway is `server/nebius-review.mjs`, also mirrored into the host's server-only module. Hosting secrets must include **NEBIUS_API_KEY**; they must not be put in client scripts, `VITE_*` variables, metadata or committed configuration. Optional server settings: `NEBIUS_BASE_URL`, `NVIDIA_MODEL_NAME`, `NEBIUS_DAILY_LIMIT`, `NEBIUS_IP_HOURLY_LIMIT`. Redeploy after a secret change.

The production manifest opts into D1. Apply `hosting/migrations/0002_review_limits.sql` through the host's normal migration process. If shared quota storage is absent or unavailable, AI review fails closed. Default public-demo limits are 4 attempts per address/hour and 20 attempts/day globally, with hard maximums of 10 and 100 respectively; failed/cancelled attempts may consume a reservation. Each review makes at most two inference calls, with bounded tokens and a 90-second pipeline deadline. There are no automatic retries that silently multiply usage.

`GET /api/nebius/status` reports configuration, not proof of inference. A successful AI review includes actual requested/returned model IDs, provider request IDs where supplied, token counts where supplied, stage latency and timestamp. Export its report to retain evidence of a real run. Never publish a report containing private source or secrets.

## Test

`npm test` runs the 44 gateway tests with **mocked** provider responses. They cover endpoint/model restrictions, consent, size limits, malformed output, quotas, origin checks, secret redaction and failure recovery. They do not prove a real provider call.

The browser regression suite previously passed 63 checks on the static release. The updated browser/AI integration has its own release checks; see `docs/VALIDATION.md`. Syntax checks and static rescans do not run program tests or benchmark performance. Suggested tests in AI output are explicitly labelled **not executed**.

## Original Python agent

`original-python/` contains the original Streamlit/FastAPI/CLI program and its multi-agent orchestration. Its defaults have been updated to Token Factory's US endpoint and NVIDIA Nemotron models only. For that interface, create a virtual environment, install `original-python/requirements.txt`, configure its `.env`, then run `streamlit run app/main.py` from that folder. Its original README documents the agent loop and repository workflows. Historical benchmark claims in that README are inherited project material and were not independently rerun for this web revision.

## Challenge documentation

- [Architecture and trust boundaries](docs/ARCHITECTURE.md)
- [Significant changes to the existing project](docs/SIGNIFICANT-UPDATES.md)
- [Nebius/NVIDIA implementation feedback and unmeasured items](docs/NEBIUS-FEEDBACK.md)
- [Validation and remaining release gates](docs/VALIDATION.md)

The required demo video is intentionally outside the current work. No claim is made that the full challenge submission is finished before a real NVIDIA-on-Nebius inference has been verified and the remaining submission materials are completed.

## License

Project-authored code is MIT licensed; see the root [LICENSE](LICENSE). Third-party components keep their own licenses: Pyodide MPL-2.0 is retained in `licenses/Pyodide-MPL-2.0.txt`; Acorn's MIT terms are in `ACORN-LICENSE`; Python wheels include their package license metadata. The MIT license does not replace third-party license terms. NVIDIA model usage is subject to the relevant NVIDIA open-model license and Nebius service terms.

Official references: [Nebius quickstart](https://docs.tokenfactory.nebius.com/quickstart), [Nebius's NVIDIA model cookbook](https://github.com/nebius/token-factory-cookbook/tree/main/models/nemotron), [Nemotron 3 Super example](https://github.com/nebius/token-factory-cookbook/blob/main/models/nemotron/nemotron3-super-120B.md).
