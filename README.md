# PatchPilot Lab

Public browser-local code audit workbench and complete original source explorer. Publish this directory from the main branch repository root using GitHub Pages. No server, API key, external hosting or build command is needed.

The original source archive is `patchpilot-source.zip` (unchanged). All 39 source files are visible in `source-files.json` and the website's file explorer. `engine-*.py` are unchanged copies of the original scanner, AST analyser, rule catalogue, models and deterministic fixers. `audit.py`, `worker.js`, and the browser interface adapt them to a browser-local Python worker. Submitted code is never executed or sent to a server.

The Pyodide 314.0.7 runtime and pydantic wheels are vendored here for independent hosting. See `LICENSE` for Pyodide's license; individual Python wheels include package license metadata. The original source ZIP is supplied by the project owner. This repository does not assert a license over its original code.

Full Python app features such as Nebius AI reasoning and remote Git workflows need the original README's local setup and credentials. They are not enabled in the browser workbench. Findings require human review; test patches before applying them.

## Upgraded diagnostics

Python now includes Pyflakes 4.0.3 name/scope diagnostics, syntax explanations and a supported missing-colon proposal, selected runtime pitfalls, and conditional performance proposals with code examples. JavaScript includes Acorn 8.19.0 parsing, selected bugs and nested-loop efficiency hints, alongside original security rules. TypeScript retains security-pattern checks only. Pyflakes is bundled in pyflakes.whl (its license is included in wheel metadata); Acorn's license is ACORN-LICENSE.

These checks do not execute submitted code, prove correctness, find every logical issue, or benchmark performance. Suggested efficiency examples are not automatically applied. Security and supported syntax patches are shown for review, syntax checked, and rescanned.

## Final review improvements

The workbench includes search and severity/category filters, keyboard analysis (Ctrl/Cmd+Enter), keyboard-accessible file upload, live file-size feedback, and explicit coverage by language. Scan results are tied to a request and editor revision: changing code, language, or filename during a scan discards the old result. File/example reads also cannot overwrite newer edits. Cancel, timeout, worker startup failure, and retry preserve the editor text and show a recovery action.

Additional Python checks cover compile-context errors (without executing code), negative/string literal indexes, calls to literals, incompatible literal string addition, and tuple assertions that always pass. Security text checks continue when Python syntax is broken. JavaScript adds literal null access, calls to non-callable literals, BigInt/Number arithmetic, duplicate object keys, unreachable statements, and conditional reviews for async Promise executors and assignments in conditions. Loop-cost checks reset at function boundaries. JavaScript does not include general undefined-name or type analysis; JSX and TypeScript syntax are not supported.

Fix syntax first and reanalyse: a repaired program can reveal additional findings. No finite static rule set detects all errors. Behavioural tests, dependency checks, type checking, and profiling remain project-level work.
