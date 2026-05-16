# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Security Architecture

### Input Validation
- All tool parameters validated against Strix XML schemas
- Required parameter enforcement at handler level
- Type coercion via Strix argument parser

### Sandbox Authentication
- Bearer token required for sandbox execution
- Token masked in config resource (last 8 chars)
- Token validated before HTTP request to ToolServer

### Dynamic Handler Safety
- `exec()` isolated with controlled globals
- No user input in exec'd code strings
- Handler functions have fixed signature

### Timeout Protection
- Sandbox tools: 150s total timeout (httpx)
- ToolServer request timeout: configurable via `strix_sandbox_execution_timeout`

## Reported Vulnerabilities

No known vulnerabilities.

## Dependencies

| Package | Purpose | Risk |
|---|---|---|
| `mcp` | MCP protocol SDK | Low — Anthropic maintained |
| `httpx` | Async HTTP client | Low — well-audited |
| `defusedxml` | Safe XML parsing | Low — prevents XXE |
| `pydantic` | Validation | Low — widely used |
