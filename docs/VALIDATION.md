# Validation

- Original Python agent: 118 tests passed offline; three SyntaxWarnings arose from deliberately malformed fuzz-test inputs. No provider inference was performed by this suite.
- Standalone Node server: 11 HTTP checks passed, including private-path rejection, consent, cross-origin rejection, missing-key handling and runtime asset serving.
- Gateway: 44 Node tests passed using explicitly mocked provider responses.
- Quota migration: 3 checks passed against real SQLite SQL (first reservation, increment, exhausted limit).
- Static browser release: 63 live browser checks passed before adding Nebius UI; these are prior-release evidence, not a claim that the new AI flow has run against Nebius.
- Updated frontend integration: 78 browser checks passed on the hosted deployment. Local Python/JavaScript checks and proposal syntax validation used the actual browser runtime; AI responses were explicitly mocked. Checks include consent, output escaping, proposal loading, cancellation, stale-response rejection, mobile layout and removal of full-project download routes.
- Hosted server deployment: deployed successfully with quota storage configured; no Nebius API key was configured at verification time.
- Real NVIDIA-on-Nebius inference: pending owner secret configuration and a successful live review. A configuration status alone is not sufficient.
- Runtime execution of submitted/generated code and performance benchmarking: not performed by this application.
- Demo video and other final submission materials: deferred at the participant's request.
