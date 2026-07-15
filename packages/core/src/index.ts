import { randomUUID } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema
} from "@modelcontextprotocol/sdk/types.js";
import {
  targetServerConfigSchema,
  type TargetServerConfig
} from "@mcp-warden/shared";

export type LifecycleEvent = {
  eventId: string;
  timestamp: string;
  eventType: "target_connecting" | "target_connected" | "tools_listed" | "tool_forwarded" | "target_closed";
  payload: Record<string, unknown>;
};

type EventSink = (event: LifecycleEvent) => void;

export class WardenTargetClient {
  readonly #config: TargetServerConfig;
  readonly #client: Client;
  readonly #transport: StdioClientTransport;
  readonly #emit: EventSink;
  #connected = false;

  constructor(config: TargetServerConfig, emit: EventSink = () => undefined) {
    this.#config = targetServerConfigSchema.parse(config);
    this.#emit = emit;
    this.#client = new Client(
      { name: "mcp-warden", version: "0.1.0" },
      { capabilities: {} }
    );
    const transportOptions: ConstructorParameters<typeof StdioClientTransport>[0] = {
      command: this.#config.command,
      args: this.#config.args,
      stderr: "pipe"
    };
    if (this.#config.cwd !== undefined) transportOptions.cwd = this.#config.cwd;
    this.#transport = new StdioClientTransport(transportOptions);
  }

  async connect(): Promise<void> {
    if (this.#connected) return;
    this.#event("target_connecting", { targetName: this.#config.name });
    await this.#client.connect(this.#transport);
    this.#connected = true;
    this.#event("target_connected", { targetName: this.#config.name });
  }

  async listTools() {
    this.#assertConnected();
    const result = await this.#client.listTools();
    this.#event("tools_listed", { count: result.tools.length });
    return result;
  }

  async callTool(name: string, args: Record<string, unknown>) {
    this.#assertConnected();
    const result = await this.#client.callTool({ name, arguments: args });
    this.#event("tool_forwarded", { toolName: name });
    return result;
  }

  async close(): Promise<void> {
    await this.#transport.close();
    this.#connected = false;
    this.#event("target_closed", { targetName: this.#config.name });
  }

  #assertConnected(): void {
    if (!this.#connected) throw new Error("Target MCP client is not connected");
  }

  #event(eventType: LifecycleEvent["eventType"], payload: Record<string, unknown>): void {
    this.#emit({ eventId: randomUUID(), timestamp: new Date().toISOString(), eventType, payload });
  }
}

export class WardenProxy {
  readonly #target: WardenTargetClient;
  readonly #server: Server;

  constructor(config: TargetServerConfig, emit?: EventSink) {
    this.#target = new WardenTargetClient(config, emit);
    this.#server = new Server(
      { name: "mcp-warden", version: "0.1.0" },
      { capabilities: { tools: {} } }
    );
    this.#server.setRequestHandler(ListToolsRequestSchema, async () => this.#target.listTools());
    this.#server.setRequestHandler(CallToolRequestSchema, async (request) => {
      return this.#target.callTool(request.params.name, request.params.arguments ?? {});
    });
  }

  async runStdio(): Promise<void> {
    await this.#target.connect();
    await this.#server.connect(new StdioServerTransport());
  }

  async close(): Promise<void> {
    await Promise.allSettled([this.#server.close(), this.#target.close()]);
  }
}

