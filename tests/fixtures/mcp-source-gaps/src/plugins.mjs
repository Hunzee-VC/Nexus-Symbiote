import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "plugins", version: "1.0.0" });
const plugin = await import(process.env.NOTES_PLUGIN);
plugin.register(server);
