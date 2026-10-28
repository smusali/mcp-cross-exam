from typing import Annotated

import anyio
from mcp.server.mcpserver import MCPServer
from pydantic import Field

server = MCPServer("echo")


@server.tool(description="Echo text.", structured_output=False)
def echo(text: Annotated[str, Field(max_length=64, description="Text to echo.")]) -> str:
    return text


def main() -> None:
    anyio.run(server.run_stdio_async)


if __name__ == "__main__":
    main()
