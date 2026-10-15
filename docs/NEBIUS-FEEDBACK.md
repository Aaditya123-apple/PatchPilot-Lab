# Nebius and NVIDIA implementation feedback

## Observations from implementation

Nebius's OpenAI-compatible chat-completion API fits the project's existing request/response structure; the gateway can use standard server-side HTTP without adding a browser SDK or exposing the key. Separate system/user messages and JSON output are useful for structured review. Reporting the provider's request/model/usage fields makes real inference distinguishable from local checks and mocks.

Documentation shows model IDs with different capitalization and regional endpoints. The exact catalog ID and endpoint should be confirmed in the participant's Token Factory project. The application therefore exposes the requested model and endpoint host and fails clearly on authentication/model errors, rather than silently switching providers.

## Not yet measured

No real inference was available when this document was first written because the host had no NEBIUS_API_KEY secret. Mock tests do not establish provider accuracy, latency, cost or availability. Add a real exported review's non-sensitive request/model/token/latency evidence after configuration; compare representative bugs and correct programs before making quality or speed claims.

Nebius AI Cloud, Serverless Endpoints/Jobs, NemoClaw and OpenShell have not been used in this hosted revision. They are not claimed as integrations. The challenge describes Serverless deployment as encouraged, not required. The selected path is NVIDIA Nemotron inference on Nebius Token Factory.
