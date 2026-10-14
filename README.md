# PatchPilot Lab

Public browser-local code audit workbench and complete original source explorer. Publish this directory from the main branch repository root using GitHub Pages. No server, API key, external hosting or build command is needed.

The original source archive is `patchpilot-source.zip` (unchanged). All 39 source files are visible in `source-files.json` and the website's file explorer. `engine-*.py` are unchanged copies of the original scanner, AST analyser, rule catalogue, models and deterministic fixers. `audit.py`, `worker.js`, and the browser interface adapt them to a browser-local Python worker. Submitted code is never executed or sent to a server.

The Pyodide 314.0.7 runtime and pydantic wheels are vendored here for independent hosting. See `LICENSE` for Pyodide's license; individual Python wheels include package license metadata. The original source ZIP is supplied by the project owner. This repository does not assert a license over its original code.

Full Python app features such as Nebius AI reasoning and remote Git workflows need the original README's local setup and credentials. They are not enabled in the browser workbench. Findings require human review; test patches before applying them.
