"""
Strix MCP Server — Expose Strix tools via Model Context Protocol.

Reads the Strix tool registry and exposes each registered tool as an MCP tool.
Handles execution routing (local vs sandbox via ToolServer).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

# ── Paths ──────────────────────────────────────────────────────────────
STRIX_REPO = Path(os.getenv("STRIX_REPO", "./strix"))  # Path to Strix repo (set env var)
sys.path.insert(0, str(STRIX_REPO))

# ── Config ─────────────────────────────────────────────────────────────
SANDBOX_URL = os.getenv("STRIX_SANDBOX_TOOL_SERVER_URL", "")
SANDBOX_TOKEN = os.getenv("STRIX_SANDBOX_TOKEN", "")
SANDBOX_AGENT_ID = os.getenv("STRIX_SANDBOX_AGENT_ID", "default")

# ── Rate limiting ──────────────────────────────────────────────────────
_rate_limit_window: dict[str, list[float]] = {}
_RATE_LIMIT_MAX = 100  # requests per window
_RATE_LIMIT_WINDOW = 60  # seconds

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("strix-mcp")

# ── Server ─────────────────────────────────────────────────────────────
mcp = FastMCP(
    name="strix-mcp-server",
    instructions="Exposes Strix penetration testing tools via MCP. Tools include nmap scanning, vulnerability detection, web probing, subdomain enumeration, and more.",
)

# ── Registry loader ────────────────────────────────────────────────────
# Global storage for tool entries (functions can't be serialized in exec)
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
        logger.warning(f"Strix registry not importable (expected if running outside sandbox): {e}")
        _REGISTRY_CACHE = []
        return []


# ── XML description parser ─────────────────────────────────────────────
def _parse_xml_description(xml_schema: str) -> str:
    """Extract description from XML schema string, handling malformed examples section."""
    if not xml_schema:
        return ""

    try:
        # Strip the <examples> section to avoid parsing errors from malformed XML
        clean = xml_schema
        examples_start = clean.find("<examples>")
        examples_end = clean.find("</examples>")
        if examples_start != -1 and examples_end != -1:
            clean = clean[:examples_start] + clean[examples_end + len("</examples>") :]

        import defusedxml.ElementTree as ET

        root = ET.fromstring(clean)

        # Navigate <tools> -> <tool> hierarchy
        tools_elem = root.find("tools")
        if tools_elem is not None:
            tool_elem = tools_elem.find("tool")
        else:
            tool_elem = root.find("tool")

        if tool_elem is not None:
            parts = []
            desc_elem = tool_elem.find("description")
            if desc_elem is not None and desc_elem.text:
                parts.append(desc_elem.text.strip())
            details_elem = tool_elem.find("details")
            if details_elem is not None and details_elem.text:
                parts.append("\n\nDetails:\n" + details_elem.text.strip())
            notes_elem = tool_elem.find("notes")
            if notes_elem is not None and notes_elem.text:
                parts.append("\n\nNotes:\n" + notes_elem.text.strip())
            if parts:
                return "\n".join(parts)

        # Direct <description> element (no wrapper)
        desc = root.find("description")
        if desc is not None and desc.text:
            return desc.text.strip()

        # Fallback: regex extraction
        import re

        desc_match = re.search(r"<description>(.*?)</description>", clean, re.DOTALL)
        if desc_match:
            return desc_match.group(1).strip()

    except Exception:
        pass
    return ""


# ── Parameter schema helpers ───────────────────────────────────────────
def _get_param_schema(tool_name: str) -> dict[str, Any] | None:
    """Get parameter schema for a tool by name."""
    try:
        from strix.tools.registry import get_tool_param_schema

        return get_tool_param_schema(tool_name)  # type: ignore[no-any-return]
    except Exception:
        return None


def _sanitize_param_value(value: Any, expected_type: str) -> Any:
    """Sanitize a parameter value to expected type."""
    if value is None:
        return None
    if expected_type == "string":
        return str(value) if not isinstance(value, str) else value
    if expected_type == "integer":
        try:
            return int(value)
        except (ValueError, TypeError):
            return 0
    if expected_type == "number":
        try:
            return float(value)
        except (ValueError, TypeError):
            return 0.0
    if expected_type == "boolean":
        if isinstance(value, bool):
            return value
        return str(value).lower() in ("true", "1", "yes")
    if expected_type == "array":
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            try:
                import json

                parsed = json.loads(value)
                if isinstance(parsed, list):
                    return parsed
            except (json.JSONDecodeError, TypeError):
                return [value] if value else []
    if expected_type == "object":
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                import json

                parsed = json.loads(value)
                if isinstance(parsed, dict):
                    return parsed
            except (json.JSONDecodeError, TypeError):
                return {}
    return value


def _get_param_type(func: Any, param_name: str) -> str:
    """Infer JSON schema type from Python function signature."""
    try:
        import inspect

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
    """Check if tool call is within rate limit. Returns True if allowed."""
    import time

    now = time.time()
    key = f"tool:{tool_name}"
    if key not in _rate_limit_window:
        _rate_limit_window[key] = []
    # Clean old entries
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

    # Convert arguments using Strix's argument parser
    try:
        from strix.tools.argument_parser import convert_arguments

        converted = convert_arguments(tool_func, kwargs)
    except Exception:
        converted = kwargs

    # Check if tool needs agent_state
    try:
        import inspect

        sig = inspect.signature(tool_func)
        if "agent_state" in sig.parameters:
            converted["agent_state"] = None
    except Exception:
        pass

    result = tool_func(**converted)
    if asyncio.iscoroutine(result):
        result = await result
    return result


# ── MCP Tools ──────────────────────────────────────────────────────────
def _register_tools():
    """Register all Strix tools as MCP tools."""
    registry = _load_registry()

    if not registry:
        logger.info("No Strix tools found in registry. Server will expose discovery tools only.")
        return

    for tool_entry in registry:
        name = tool_entry.get("name", "unknown")
        xml_schema = tool_entry.get("xml_schema", "")
        description = _parse_xml_description(xml_schema) if xml_schema else f"Strix tool: {name}"
        sandbox_execution = tool_entry.get("sandbox_execution", True)
        module = tool_entry.get("module", "unknown")

        # Get param schema for validation
        param_schema = _get_param_schema(name)

        # Build dynamic handler with proper signature via exec
        param_names = []
        if param_schema and param_schema.get("has_params"):
            param_names = sorted(param_schema.get("params", set()))

        param_sig = ", ".join(f'{p}: str = ""' for p in param_names)
        if not param_sig:
            param_sig = 'input: "dict" = {}'

        if param_names:
            kwargs_build = "kwargs = {" + ", ".join(f'"{p}": {p}' for p in param_names) + "}"
        else:
            kwargs_build = "kwargs = dict(input)"

        handler_code = f'''
async def handler({param_sig}):
    """Execute a Strix tool via MCP."""
    {kwargs_build}
    logger.info(
        f"Executing tool \'{name}\' via MCP (sandbox={sandbox_execution}, kwargs={{list(kwargs.keys())}})"
    )

    # Validate required params
    ps = {repr(param_schema)}
    if ps and ps.get("has_params"):
        required = ps.get("required", set())
        for req_param in required:
            if req_param not in kwargs or kwargs.get(req_param) in (None, ""):
                return {{
                    "success": False,
                    "tool": "{name}",
                    "error": f"Missing required parameter: {{req_param}}",
                }}

    try:
        if {sandbox_execution}:
            result = await _execute_sandbox("{name}", kwargs)
        else:
            result = await _execute_local(_TOOL_ENTRIES.get("{name}", {{}}), kwargs)

        return {{
            "success": True,
            "tool": "{name}",
            "result": str(result) if result else "No result",
        }}
    except Exception as e:
        logger.error(f"Tool {name} failed: {{e}}")
        return {{
            "success": False,
            "tool": "{name}",
            "error": str(e),
        }}
'''
        local_ns: dict = {}
        exec(
            handler_code,
            {
                "_execute_sandbox": _execute_sandbox,
                "_execute_local": _execute_local,
                "logger": logger,
                "_TOOL_ENTRIES": _TOOL_ENTRIES,
            },
            local_ns,
        )
        handler = local_ns["handler"]
        handler.__name__ = f"strix_{name.replace('-', '_').replace('.', '_')}"
        mcp.add_tool(handler, description=f"[{module}] {description}")

    logger.info(f"Registered {len(registry)} Strix tools as MCP tools")


# ── MCP Resources ──────────────────────────────────────────────────────
@mcp.resource("strix://tools/list")
async def list_tools() -> str:
    """List all available Strix tools with their categories and descriptions."""
    registry = _load_registry()

    if not registry:
        return json.dumps(
            {"tools": [], "message": "No tools available (registry not loaded)"},
            indent=2,
        )

    tools_by_module: dict[str, list[dict]] = {}
    for entry in registry:
        module = entry.get("module", "unknown")
        if module not in tools_by_module:
            tools_by_module[module] = []
        tools_by_module[module].append(
            {
                "name": entry.get("name"),
                "sandbox": entry.get("sandbox_execution", True),
                "description": _parse_xml_description(entry.get("xml_schema", "")),
            }
        )

    return json.dumps({"tools_by_module": tools_by_module}, indent=2, default=str)


@mcp.resource("strix://config")
async def get_config() -> str:
    """Current Strix MCP server configuration."""
    config = {
        "sandbox_url": SANDBOX_URL or "(not configured)",
        "sandbox_token": "..." + SANDBOX_TOKEN[-8:] if len(SANDBOX_TOKEN) > 8 else "(not set)",
        "sandbox_agent_id": SANDBOX_AGENT_ID,
        "strix_repo": str(STRIX_REPO),
        "sandbox_mode": os.getenv("STRIX_SANDBOX_MODE", "false"),
    }
    return json.dumps(config, indent=2)


# ── MCP Prompts ────────────────────────────────────────────────────────
@mcp.prompt()
async def pentest_recon(target: str, tool: str = "all") -> str:
    """
    Generate a reconnaissance workflow for a target.

    Args:
        target: Target IP or domain to scan.
        tool: Specific tool to use, or 'all' for full recon suite.
    """
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
    """
    Generate a vulnerability scanning workflow.

    Args:
        target: Target to scan.
    """
    return f"""Eres un agente Strix ejecutando escaneo de vulnerabilidades contra {target}.

Workflow:
1. Escaneo con nuclei (plantillas default + critical)
2. Escaneo con sqlmap (si hay endpoints con parametros)
3. Escaneo con wapiti (web app)
4. Busqueda de secrets con trufflehog
5. Analisis de dependencias con semgrep

Ejecuta en orden y reporta vulnerabilidades encontradas."""


# ── Init ───────────────────────────────────────────────────────────────
_register_tools()


def main():
    """Entry point."""
    mcp.run()


if __name__ == "__main__":
    main()
