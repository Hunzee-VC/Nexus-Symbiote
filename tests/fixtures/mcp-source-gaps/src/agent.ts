import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const client = new Client({ name: "agent", version: "1.0.0" });
const transport = new StdioClientTransport({ command: "npx", args: ["-y", "notes-mcp"] });
await client.connect(transport);
