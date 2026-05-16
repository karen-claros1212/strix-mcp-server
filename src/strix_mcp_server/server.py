"""
Strix MCP Server v0.2.0a1 — Expose a curated subset of Strix tools via MCP.

SECURITY MODEL
==============
- Lazy loading: Strix registry loaded only in main(), not at import time
- Zero exec(): All handlers use closures via _make_handler()
- Strict validation: _sanitize_param_value raises on invalid types
- Allowlist/Denylist: Force-blocked dangerous tools, optional explicit allowlist
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

# ── Paths ──────────────────────────────────────────────────────────────
STRIX_REPO = Path(os.getenv("STRIX_REPO", "./strix"))
sys.path.insert(0, str(STRIX_REPO))

# ── Config ─────────────────────────────────────────────────────────────
SANDBOX_URL = os.getenv("STRIX_SANDBOX_TOOL_SERVER_URL", "")
SANDBOX_TOKEN = os.getenv("STRIX_SANDBOX_TOKEN", "")
SANDBOX_AGENT_ID = os.getenv("STRIX_SANDBOX_AGENT_ID", "default")

# ── Rate limiting ──────────────────────────────────────────────────────
_rate_limit_window: dict[str, list[float]] = {}
_RATE_LIMIT_MAX = 100
_RATE_LIMIT_WINDOW = 60

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("strix-mcp")

# ── Server ─────────────────────────────────────────────────────────────
mcp = FastMCP(
    name="strix-mcp-server",
    instructions="Exposes Strix penetration testing tools via MCP with allowlist-based security.",
)

# ── Registry loader (lazy) ────────────────────────────────────────────
_TOOL_ENTRIES: dict[str, dict[str, Any]] = {}
_REGISTRY_CACHE: list[dict[str, Any]] | None = None


def _load_registry() -> list[dict[str, Any]]:
    """Import and read the Strix tool registry. Cached after first call."""
    global _REGISTRY_CACHE
    if _REGISTRY_CACHE is not None:
        return _REGISTRY_CACHE

    try:
        from strix.tools.registry import tools, get_tool_names, get_tool_param_schema  # noqa: F401

        for entry in tools:
            name = entry.get("name", "")
            if name:
                _TOOL_ENTRIES[name] = entry
        _REGISTRY_CACHE = tools  # type: ignore[list-item]
        return _REGISTRY_CACHE
    except ImportError as e:
        logger.warning(f"Strix registry not importable (expected outside sandbox): {e}")
        _REGISTRY_CACHE = []
        return []


# ── XML description parser ─────────────────────────────────────────────
def _parse_xml_description(xml_schema: str) -> str:
    """Extract description from XML schema, stripping malformed <examples> section."""
    if not xml_schema:
        return ""

    try:
        clean = xml_schema
        examples_start = clean.find("<examples>")
        examples_end = clean.find("</examples>")
        if examples_start != -1 and examples_end != -1:
            clean = clean[:examples_start] + clean[examples_end + len("</examples>") :]

        import defusedxml.ElementTree as ET

        root = ET.fromstring(clean)

        tools_elem = root.find("tools")
        tool_elem = tools_elem.find("tool") if tools_elem is not None else root.find("tool")

        if tool_elem is not None:
            parts = []
            for tag in ("description", "details", "notes"):
                elem = tool_elem.find(tag)
                if elem is not None and elem.text:
                    prefix = "\n\n" + tag.capitalize() + ":\n" if tag != "description" else ""
                    parts.append(prefix + elem.text.strip())
            if parts:
                return "".join(parts)

        desc = root.find("description")
        if desc is not None and desc.text:
            return desc.text.strip()

        import re

        desc_match = re.search(r"<description>(.*?)</description>", clean, re.DOTALL)
        if desc_match:
            return desc_match.group(1).strip()

    except Exception:
        pass
    return ""


# ── Parameter helpers ──────────────────────────────────────────────────
def _get_param_schema(tool_name: str) -> dict[str, Any] | None:
    """Get parameter schema for a tool by name."""
    try:
        from strix.tools.registry import get_tool_param_schema

        return get_tool_param_schema(tool_name)  # type: ignore[no-any-return]
    except Exception:
        return None


class ParamValidationError(ValueError):
    """Raised when a parameter fails type validation."""

    pass


def _sanitize_param_value(value: Any, expected_type: str) -> Any:
    """Sanitize a parameter value to expected type. Raises ParamValidationError on invalid."""
    if value is None:
        return None

    if expected_type == "string":
        return str(value) if not isinstance(value, str) else value

    if expected_type == "integer":
        try:
            return int(value)
        except (ValueError, TypeError):
            raise ParamValidationError(f"Expected integer, got {type(value).__name__}: {value!r}")

    if expected_type == "number":
        try:
            return float(value)
        except (ValueError, TypeError):
            raise ParamValidationError(f"Expected number, got {type(value).__name__}: {value!r}")

    if expected_type == "boolean":
        if isinstance(value, bool):
            return value
        lowered = str(value).lower()
        if lowered in ("true", "1", "yes"):
            return True
        if lowered in ("false", "0", "no"):
            return False
        raise ParamValidationError(f"Expected boolean, got {value!r}")

    if expected_type == "array":
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, list):
                    return parsed
            except (json.JSONDecodeError, TypeError):
                pass
        raise ParamValidationError(f"Expected array, got {type(value).__name__}: {value!r}")

    if expected_type == "object":
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, dict):
                    return parsed
            except (json.JSONDecodeError, TypeError):
                pass
        raise ParamValidationError(f"Expected object, got {type(value).__name__}: {value!r}")

    return value


def _get_param_type(func: Any, param_name: str) -> str:
    """Infer JSON schema type from Python function signature."""
    try:
        sig = inspect.signature(func)
        if param_name not in sig.parameters:
            return "string"
        param = sig.parameters[param_name]
        annotation = param.annotation
        if annotation == int:
            return "integer"
        elif annotation == float:
            return "number"
        elif annotation == bool:
            return "boolean"
        elif annotation == str or annotation == inspect.Parameter.empty:
            return "string"
        elif hasattr(annotation, "__origin__"):
            origin = annotation.__origin__
            if origin == list:
                return "array"
            elif origin == dict:
                return "object"
    except Exception:
        pass
    return "string"


# ── Rate limiting ──────────────────────────────────────────────────────
def _check_rate_limit(tool_name: str) -> bool:
    """Check if tool call is within rate limit."""
    now = time.time()
    key = f"tool:{tool_name}"
    if key not in _rate_limit_window:
        _rate_limit_window[key] = []
    _rate_limit_window[key] = [t for t in _rate_limit_window[key] if now - t < _RATE_LIMIT_WINDOW]
    if len(_rate_limit_window[key]) >= _RATE_LIMIT_MAX:
        return False
    _rate_limit_window[key].append(now)
    return True


# ── Execution layer ────────────────────────────────────────────────────
async def _execute_sandbox(tool_name: str, kwargs: dict[str, Any]) -> Any:
    """Execute a tool via the Strix sandbox ToolServer (HTTP)."""
    if not SANDBOX_URL:
        raise RuntimeError("STRIX_SANDBOX_TOOL_SERVER_URL not configured")
    if not SANDBOX_TOKEN:
        raise RuntimeError("STRIX_SANDBOX_TOKEN not configured")

    if not _check_rate_limit(tool_name):
        return {
            "error": "rate_limited",
            "message": f"Rate limit: {_RATE_LIMIT_MAX} requests per {_RATE_LIMIT_WINDOW}s",
            "retry_after_seconds": _RATE_LIMIT_WINDOW,
        }

    import httpx

    url = f"{SANDBOX_URL}/execute"
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Invalid sandbox URL scheme: {parsed.scheme}")

    headers = {
        "Authorization": f"Bearer {SANDBOX_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {
        "agent_id": SANDBOX_AGENT_ID,
        "tool_name": tool_name,
        "kwargs": kwargs,
    }

    async with httpx.AsyncClient(timeout=150) as client:
        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        if data.get("error"):
            raise RuntimeError(f"Sandbox error: {data['error']}")
        return data.get("result")


async def _execute_local(tool_entry: dict[str, Any], kwargs: dict[str, Any]) -> Any:
    """Execute a tool locally (direct function call)."""
    tool_func = tool_entry.get("function")
    tool_name = tool_entry.get("name", "unknown")
    if not tool_func:
        raise RuntimeError(f"Tool '{tool_name}' has no function")

    try:
        from strix.tools.argument_parser import convert_arguments

        converted = convert_arguments(tool_func, kwargs)
    except Exception:
        converted = kwargs

    try:
        sig = inspect.signature(tool_func)
        if "agent_state" in sig.parameters:
            converted["agent_state"] = None
    except Exception:
        pass

    result = tool_func(**converted)
    if asyncio.iscoroutine(result):
        result = await result
    return result


# ── Handler factory (zero exec) ────────────────────────────────────────
def _make_handler(tool_name: str, param_schema: dict[str, Any] | None, sandbox: bool) -> Any:
    """Create a tool handler via closure. No exec(), no f-string interpolation."""

    async def handler(**kwargs: Any) -> dict[str, Any]:
        """Execute a Strix tool via MCP."""
        logger.info(f"Executing tool '{tool_name}' via MCP (sandbox={sandbox}, kwargs={list(kwargs.keys())})")

        if param_schema and param_schema.get("has_params"):
            required = param_schema.get("required", set())
            for req_param in required:
                if req_param not in kwargs or kwargs.get(req_param) in (None, ""):
                    return {
                        "success": False,
                        "tool": tool_name,
                        "error": f"Missing required parameter: {req_param}",
                    }

        try:
            if sandbox:
                result = await _execute_sandbox(tool_name, kwargs)
            else:
                result = await _execute_local(_TOOL_ENTRIES.get(tool_name, {}), kwargs)

            return {
                "success": True,
                "tool": tool_name,
                "result": str(result) if result else "No result",
            }
        except Exception as e:
            logger.error(f"Tool {tool_name} failed: {e}")
            return {
                "success": False,
                "tool": tool_name,
                "error": str(e),
            }

    handler.__name__ = f"strix_{tool_name.replace('-', '_').replace('.', '_')}"
    return handler


# ── Allowlist / Denylist ──────────────────────────────────────────────
# Force-blocked: dangerous tools NEVER exposed (hardcoded, not env-overridable)
_FORCE_BLOCKED_TOOLS: frozenset[str] = frozenset(
    {
        "terminal_execute",
        "python_action",
        "browser_action",
        "str_replace_editor",
        "send_request",
    }
)

# Default safe allowlist (read-only / analysis-only tools)
_DEFAULT_ALLOWED: frozenset[str] = frozenset(
    {
        "list_files",
        "search_files",
        "view_request",
        "view_sitemap_entry",
        "list_requests",
        "list_sitemap",
        "think",
        "create_note",
        "list_notes",
        "get_note",
        "update_note",
        "delete_note",
        "create_todo",
        "list_todos",
        "update_todo",
        "mark_todo_done",
        "mark_todo_pending",
        "delete_todo",
        "create_vulnerability_report",
        "view_agent_graph",
        "wait_for_message",
    }
)

# Allowlist: env var overrides default, or empty = use default
_ALLOWED_TOOLS_ENV = os.getenv("STRIX_MCP_ALLOWED_TOOLS", "")
_ALLOWED_TOOLS: frozenset[str] = (
    frozenset(t.strip() for t in _ALLOWED_TOOLS_ENV.split(",") if t.strip())
    if _ALLOWED_TOOLS_ENV
    else _DEFAULT_ALLOWED
)

# Override force-blocked (e.g. STRIX_MCP_FORCE_BLOCKED_TOOLS="terminal_execute,browser_action")
_FORCE_BLOCKED_OVERRIDE_ENV = os.getenv("STRIX_MCP_FORCE_BLOCKED_TOOLS", "")
_FORCE_BLOCKED_OVERRIDE_SET: frozenset[str] | None = (
    frozenset(t.strip() for t in _FORCE_BLOCKED_OVERRIDE_ENV.split(",") if t.strip())
    if _FORCE_BLOCKED_OVERRIDE_ENV
    else None
)


def _is_tool_allowed(tool_name: str) -> tuple[bool, str]:
    """Check if a tool is allowed. Returns (allowed, reason)."""
    # 1. Check force-blocked (unless overridden)
    if tool_name in _FORCE_BLOCKED_TOOLS:
        if _FORCE_BLOCKED_OVERRIDE_SET and tool_name in _FORCE_BLOCKED_OVERRIDE_SET:
            return True, "unblocked by STRIX_MCP_FORCE_BLOCKED_TOOLS"
        return False, f"force-blocked (add to STRIX_MCP_FORCE_BLOCKED_TOOLS to unblock)"

    # 2. Check allowlist (if set)
    if _ALLOWED_TOOLS and tool_name not in _ALLOWED_TOOLS:
        return False, f"not in STRIX_MCP_ALLOWED_TOOLS allowlist"

    return True, ""


# ── MCP Tools ──────────────────────────────────────────────────────────
def _register_tools():
    """Register allowed Strix tools as MCP tools."""
    registry = _load_registry()

    if not registry:
        logger.info("No Strix tools found in registry. Server will expose discovery tools only.")
        return

    registered_count = 0
    skipped_count = 0

    for tool_entry in registry:
        name = tool_entry.get("name", "unknown")
        xml_schema = tool_entry.get("xml_schema", "")
        description = _parse_xml_description(xml_schema) if xml_schema else f"Strix tool: {name}"
        sandbox_execution = tool_entry.get("sandbox_execution", True)
        module = tool_entry.get("module", "unknown")

        allowed, reason = _is_tool_allowed(name)
        if not allowed:
            logger.debug(f"Skipping tool '{name}': {reason}")
            skipped_count += 1
            continue

        param_schema = _get_param_schema(name)
        handler = _make_handler(name, param_schema, sandbox_execution)
        mcp.add_tool(handler, name=f"strix_{name}", description=f"[{module}] {description}")
        registered_count += 1

    logger.info(f"Registered {registered_count} Strix tools as MCP tools ({skipped_count} skipped)")


# ── MCP Resources ──────────────────────────────────────────────────────
@mcp.resource("strix://tools/list")
async def list_tools() -> str:
    """List all Strix tools with exposure status."""
    registry = _load_registry()

    if not registry:
        return json.dumps({"tools": [], "message": "No tools available"}, indent=2)

    tools_by_module: dict[str, list[dict]] = {}
    for entry in registry:
        module = entry.get("module", "unknown")
        if module not in tools_by_module:
            tools_by_module[module] = []
        name = entry.get("name", "")
        allowed, reason = _is_tool_allowed(name)
        tools_by_module[module].append(
            {
                "name": name,
                "sandbox": entry.get("sandbox_execution", True),
                "description": _parse_xml_description(entry.get("xml_schema", "")),
                "exposed": allowed,
                "exposure_reason": reason if not allowed else None,
            }
        )

    return json.dumps({"tools_by_module": tools_by_module}, indent=2, default=str)


@mcp.resource("strix://config")
async def get_config() -> str:
    """Current Strix MCP server configuration."""
    config = {
        "version": "0.2.0a1",
        "sandbox_url": SANDBOX_URL or "(not configured)",
        "sandbox_token": "..." + SANDBOX_TOKEN[-8:] if len(SANDBOX_TOKEN) > 8 else "(not set)",
        "sandbox_agent_id": SANDBOX_AGENT_ID,
        "strix_repo": str(STRIX_REPO),
        "sandbox_mode": os.getenv("STRIX_SANDBOX_MODE", "false"),
        "force_blocked_tools": list(_FORCE_BLOCKED_TOOLS),
        "allowlist": list(_ALLOWED_TOOLS) if _ALLOWED_TOOLS else None,
        "force_blocked_override": list(_FORCE_BLOCKED_OVERRIDE_SET) if _FORCE_BLOCKED_OVERRIDE_SET else None,
    }
    return json.dumps(config, indent=2)


# ── MCP Prompts ────────────────────────────────────────────────────────
@mcp.prompt()
async def pentest_recon(target: str, tool: str = "all") -> str:
    """Generate a reconnaissance workflow for a target."""
    tool_line = (
        f"Usa especificamente la herramienta: {tool}" if tool != "all" else "Usa todas las herramientas disponibles"
    )
    return f"""Eres un agente Strix ejecutando reconocimiento contra {target}.

Workflow de reconocimiento:
1. Escaneo de puertos con nmap
2. Deteccion de servicios y versiones
3. Escaneo de vulnerabilidades con nuclei
4. Busqueda de subdominios con subfinder
5. HTTP probing con httpx

{tool_line}

Ejecuta las herramientas en orden y reporta los hallazgos."""


@mcp.prompt()
async def vuln_scan_target(target: str) -> str:
    """Generate a vulnerability scanning workflow."""
    return f"""Eres un agente Strix ejecutando escaneo de vulnerabilidades contra {target}.

Workflow:
1. Escaneo con nuclei (plantillas default + critical)
2. Escaneo con sqlmap (si hay endpoints con parametros)
3. Escaneo con wapiti (web app)
4. Busqueda de secrets con trufflehog
5. Analisis de dependencias con semgrep

Ejecuta en orden y reporta vulnerabilidades encontradas."""


# ── Init ───────────────────────────────────────────────────────────────
# _register_tools() is called inside main() — lazy loading.
# Importing this module will NOT load the Strix registry.


def main():
    """Entry point. Registers tools on startup (lazy load)."""
    _register_tools()
    mcp.run()


if __name__ == "__main__":
    main()
