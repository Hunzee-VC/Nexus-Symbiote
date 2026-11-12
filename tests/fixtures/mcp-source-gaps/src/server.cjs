const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");

const server = new McpServer({ name: "notes", version: "1.0.0" });
server.registerTool("write_note", {}, async () => ({ content: [] }));
