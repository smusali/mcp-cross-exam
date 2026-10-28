from __future__ import annotations

import json
import sys
from collections.abc import Mapping

_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["text"],
    "properties": {
        "text": {"type": "string", "maxLength": 64, "description": "Text to echo."},
    },
}


def main() -> None:
    for line in sys.stdin:
        if not line.strip():
            continue
        message = json.loads(line)
        if not isinstance(message, dict):
            continue
        reply = _answer(message)
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()


def _answer(message: Mapping[str, object]) -> dict[str, object] | None:
    method = message.get("method")
    if "id" not in message:
        return None
    rpc_id = message.get("id")
    if not isinstance(method, str):
        return _error(rpc_id, -32600, "Invalid request")
    params = message.get("params")
    body = params if isinstance(params, dict) else {}
    if method == "initialize":
        return _result(
            rpc_id,
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "strict", "version": "0"},
            },
        )
    if method == "ping":
        return _result(rpc_id, {})
    if method == "tools/list":
        return _result(
            rpc_id,
            {
                "tools": [
                    {
                        "name": "echo",
                        "description": "Echo text.",
                        "inputSchema": _SCHEMA,
                    }
                ]
            },
        )
    if method == "tools/call":
        return _call(rpc_id, body)
    return _error(rpc_id, -32601, "Method not found")


def _call(rpc_id: object, params: Mapping[str, object]) -> dict[str, object]:
    name = params.get("name")
    if name != "echo":
        return _error(rpc_id, -32602, "Unknown tool")
    arguments = params.get("arguments")
    if not isinstance(arguments, dict) or set(arguments) != {"text"}:
        return _invalid(rpc_id, "text")
    text = arguments.get("text")
    if not isinstance(text, str) or len(text) > 64:
        return _invalid(rpc_id, "text")
    return _result(rpc_id, {"content": [{"type": "text", "text": text}], "isError": False})


def _invalid(rpc_id: object, name: str) -> dict[str, object]:
    return _result(
        rpc_id,
        {"content": [{"type": "text", "text": f"invalid argument {name}"}], "isError": True},
    )


def _result(rpc_id: object, result: dict[str, object]) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


def _error(rpc_id: object, code: int, message: str) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}


if __name__ == "__main__":
    main()
