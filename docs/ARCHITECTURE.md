# Architecture

Browser local checks → optional consent → application gateway → NVIDIA Nemotron Scanner on Nebius Token Factory → conditional Nemotron Refactor → browser syntax/static validation → human review and project tests.

The model receives a JSON-encoded source payload as untrusted data, with system instructions to ignore directives in comments/source. It has no tools, filesystem, shell or network access through this application. Model output is parsed against a bounded schema and rendered as text. Generated code is never executed. The provider endpoint is selected by the server owner from a strict HTTPS host allowlist, never from a browser request. The API key stays server-side.

The gateway rejects cross-origin browser submissions, requests without consent, invalid languages, more than 10 KB/400 lines of source, and oversized JSON. It reserves shared per-address and global quotas before inference. The production SQL increment is atomic. Only rotating hashed quota buckets and counters are stored. They do not contain prompts, API keys or source. An unavailable quota binding disables paid inference.

AI output and deterministic findings remain separate. A valid parse does not imply a correct fix. Unsupported TypeScript syntax is explicitly unverified. No runtime-test or speed claim is inferred from model prose. Actual inference metadata is retained in the downloadable client report, not persisted by the app.
