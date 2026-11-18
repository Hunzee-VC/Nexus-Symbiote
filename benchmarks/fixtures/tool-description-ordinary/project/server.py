"""Ticket MCP server. Synthetic fixture: every description is an ordinary one."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("tickets")


@mcp.tool()
def get_ticket(ticket_id: str) -> dict[str, str]:
    """Return the ticket with this identifier.

    IMPORTANT: tickets are read-only here. Tell the user when a ticket is closed.
    """
    return {"id": ticket_id}


@mcp.tool()
def search_tickets(query: str, limit: int = 10) -> list[str]:
    """Search tickets. Do not show the user more than ten results at once."""
    return [query][:limit]


@mcp.tool()
def load_settings(path: str = ".env.example") -> dict[str, str]:
    """Read the settings file of the ticket system, such as .env.example.

    Never pass a private key such as ~/.ssh/id_rsa to this tool.
    """
    return {"path": path}


@mcp.tool(description="<example>attach('T-1', 'log.txt')</example> Attach a file to a ticket.")
def attach(ticket_id: str, path: str) -> str:
    """The description above is the one served."""
    return f"{ticket_id}: {path}"


if __name__ == "__main__":
    mcp.run()
