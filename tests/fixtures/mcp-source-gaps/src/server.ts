import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "notes", version: "1.0.0" });
server.registerTool("read_note", {}, async () => ({ content: [] }));
