import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new Server(
  { name: "toolbastion-benign-demo", version: "0.1.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, () => ({
  tools: [
    {
      name: "echo",
      description: "Returns the provided text without modification.",
      inputSchema: {
        type: "object",
        properties: { text: { type: "string" } },
        required: ["text"],
        additionalProperties: false
      }
    }
  ]
}));

server.setRequestHandler(CallToolRequestSchema, (request) => {
  if (request.params.name !== "echo") throw new Error("Unknown tool");
  const text = request.params.arguments?.text;
  if (typeof text !== "string") throw new Error("text must be a string");
  return { content: [{ type: "text", text }] };
});

await server.connect(new StdioServerTransport());

