import { createServer, type Server } from "node:http";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ToolBastionTargetClient } from "../../packages/core/src/index.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const image = process.env.TOOLBASTION_DOCKER_TEST_IMAGE;
const describeDocker = image === undefined ? describe.skip : describe;
const canaryEnvironmentName = "TOOLBASTION_DEMO_CANARY";
const canary = "TOOLBASTION_SYNTHETIC_CANARY_00000000-0000-4000-8000-000000000001";
let collector: Server | undefined;
let collectorUrl = "";
let received = 0;
let client: ToolBastionTargetClient | undefined;
let previousCanary: string | undefined;

describeDocker("Docker target isolation", () => {
  beforeAll(async () => {
    collector = createServer((_request, response) => {
      received += 1;
      response.writeHead(204).end();
    });
    await new Promise<void>((resolve, reject) => {
      collector!.once("error", reject);
      collector!.listen(0, "127.0.0.1", resolve);
    });
    const address = collector.address();
    if (address === null || typeof address === "string") throw new Error("Controlled collector did not bind a TCP port");
    collectorUrl = `http://127.0.0.1:${address.port}/collect`;
    previousCanary = process.env[canaryEnvironmentName];
    process.env[canaryEnvironmentName] = canary;
    client = new ToolBastionTargetClient({
      name: "docker-isolation-probe",
      command: "node",
      args: ["./examples/vulnerable-server/dist/index.js", "--demo-project-root", ".", "--demo-collector-url", collectorUrl],
      cwd: ".",
      envAllowlist: [canaryEnvironmentName],
      isolation: { provider: "docker", image: image!, user: "1000:1000" }
    }, () => undefined, () => Promise.resolve(), 10_000, root);
    await client.connect();
  }, 30_000);

  afterAll(async () => {
    await client?.close();
    await new Promise<void>((resolve, reject) => collector?.close((error) => error === undefined ? resolve() : reject(error)) ?? resolve());
    if (previousCanary === undefined) delete process.env[canaryEnvironmentName];
    else process.env[canaryEnvironmentName] = previousCanary;
  });

  it("starts the target but prevents its loopback exfiltration request from reaching the host collector", async () => {
    const tools = await client!.listTools();
    expect(tools.tools.map((tool) => tool.name)).toContain("fetch_url");
    await expect(client!.callTool("fetch_url", { url: collectorUrl })).rejects.toThrow();
    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(received).toBe(0);
  });
});
