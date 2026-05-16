# strix-mcp-server

MCP (Model Context Protocol) server that exposes Strix's penetration testing tools as MCP tools, resources, and prompts.

## Overview

This project bridges [Strix](https://github.com/usestrix/strix) — an autonomous AI agent framework for cybersecurity — with the Model Context Protocol. It enables any MCP-compatible client (Claude, Cursor, OpenCode, etc.) to execute Strix tools directly.

### Key Features

- **33 tools** exposed via MCP protocol
- **2 resources** for discovery and configuration
- **2 prompts** for standardized pentest workflows
- **Dual execution**: local mode or sandbox via Strix ToolServer
- **Parameter validation** from Strix XML schemas
- **Rich descriptions** parsed from Strix tool schemas

## Installation

```bash
pip install strix-mcp-server
```

Or install from source:

```bash
git clone https://github.com/karen-claros1212/strix-mcp-server.git
cd strix-mcp-server
pip install -e .
```

## Configuration

| Variable | Description | Default |
|---|---|---|
| `STRIX_REPO` | Path to Strix repository | `./strix` |
| `STRIX_SANDBOX_TOOL_SERVER_URL` | Sandbox ToolServer URL | (empty) |
| `STRIX_SANDBOX_TOKEN` | Bearer token for sandbox auth | (empty) |
| `STRIX_SANDBOX_AGENT_ID` | Agent ID for sandbox requests | `default` |

### Local Mode (default)

Tools execute directly without sandbox. No extra configuration needed.

### Sandbox Mode

```bash
export STRIX_SANDBOX_TOOL_SERVER_URL=http://localhost:48081
export STRIX_SANDBOX_TOKEN=your-token-here
export STRIX_SANDBOX_AGENT_ID=your-agent-id
```

## Usage

### As MCP Server (stdio)

```bash
strix-mcp
```

### In OpenCode

Add to `~/.config/opencode/opencode.json`:

```json
{
  "mcp": {
    "strix": {
      "type": "local",
      "command": ["strix-mcp"],
      "enabled": true
    }
  }
}
```

## Available Tools

| Category | Tools |
|---|---|
| **Agents** | create_agent, send_message_to_agent, agent_finish, view_agent_graph, wait_for_message |
| **Browser** | browser_action (Playwright-based) |
| **File Edit** | str_replace_editor, list_files, search_files |
| **Proxy** | send_request, list_requests, view_request, list_sitemap, view_sitemap_entry |
| **Python** | python_action |
| **Reporting** | create_vulnerability_report |
| **Terminal** | terminal_execute |
| **Thinking** | think |
| **Notes** | create_note, list_notes, get_note, update_note, delete_note |
| **Todo** | create_todo, list_todos, update_todo, mark_todo_done, mark_todo_pending, delete_todo |
| **Finish** | finish_scan |

## Resources

| URI | Description |
|---|---|
| `strix://tools/list` | List all tools by module |
| `strix://config` | Current server configuration |

## Prompts

| Prompt | Description |
|---|---|
| `pentest_recon` | Reconnaissance workflow generator |
| `vuln_scan_target` | Vulnerability scanning workflow |

## Architecture

```
┌──────────────┐     MCP JSON-RPC      ┌──────────────────┐
│  MCP Client  │ ◄──────────────────► │  strix-mcp-server │
│  (Claude,    │     stdio/HTTP       │                  │
│   Cursor,    │                      │  ┌────────────┐  │
│   OpenCode)  │                      │  │ Tool Router│  │
└──────────────┘                      │  ├────────────┤  │
                                      │  │ Local Exec │  │
│                                      │  │ Sandbox HTTP│  │
│                                      │  └────────────┘  │
│                                      │  │ Strix Registry │ │
│                                      │  └────────────────┘ │
└────────────────────────────────────────────────────────────┘
```

## Security

- All inputs validated against Strix XML schemas
- Sandbox tools require Bearer token authentication
- Token leak protection (last 8 chars only in config)
- `exec()` used only for dynamic handler generation with controlled globals
- No secrets hardcoded

## License

Apache License 2.0 — see [LICENSE](LICENSE)

## Related

- [Strix](https://github.com/usestrix/strix) — Upstream framework
- [Issue #109](https://github.com/usestrix/strix/issues/109) — MCP Support request
- [MCP Spec](https://modelcontextprotocol.io) — Protocol specification
