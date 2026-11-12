import { McpServer } from "npm:@modelcontextprotocol/sdk@1.17.0/server/mcp.js";

const server = new McpServer({ name: "notes", version: "1.0.0" });
server.registerTool("delete_note", {}, async () => ({ content: [] }));
