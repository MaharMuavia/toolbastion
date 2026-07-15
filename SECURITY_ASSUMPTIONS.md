# Security assumptions

- Warden mediates agent-initiated MCP tool calls only.
- A target process may act during startup or outside a tool call; Warden is not an OS sandbox.
- The project root and Warden installation are trusted; the target server, MCP data, model output, and policy patches are untrusted.
- v1 supports one local stdio target. Remote OAuth, complete resources/prompts passthrough, and enterprise identity are out of scope.
- Full conversation context is unavailable unless an explicit local context provider is configured.
- Audit chains are tamper-evident hashes, not signatures, and cannot protect against an attacker who can replace an entire log and its trusted anchor.
- DNS rebinding protection will be partial unless resolution pinning is implemented and tested.

