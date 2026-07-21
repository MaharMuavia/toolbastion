import { randomUUID } from "node:crypto";
import { mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { AuditLog } from "@toolbastion/audit";
import { inspectToolResult } from "@toolbastion/output-firewall";
import { ExactCallCache, evaluateDeterministic } from "@toolbastion/policy";
import { toolbastionConfigSchema } from "@toolbastion/shared";

const iterations = Number.parseInt(process.env.TOOLBASTION_BENCHMARK_ITERATIONS ?? "100", 10);
if (!Number.isInteger(iterations) || iterations < 10 || iterations > 10_000) throw new Error("TOOLBASTION_BENCHMARK_ITERATIONS must be an integer between 10 and 10000");
const root = process.cwd();
const temporary = path.join(root, ".test-tmp", `benchmark-${randomUUID()}`);
const projectRoot = path.join(temporary, "project");
const rssBefore = process.memoryUsage().rss;
await mkdir(path.join(projectRoot, "src"), { recursive: true });
await writeFile(path.join(projectRoot, "src", "index.ts"), "export {};\n", "utf8");

const config = toolbastionConfigSchema.parse({
  version: 1,
  mode: "interactive",
  project_root: projectRoot,
  target: { name: "benchmark", command: "node" },
  paths: { allow: ["./**"], deny: ["**/.env", "**/.ssh/**", "**/.aws/**"] },
  network: { default: "deny", allow_domains: ["api.github.com"] },
  judge: { enabled: false, mode: "offline" },
  tools: { default: "judge", rules: { read_project_file: { base_risk: "low", action: "allow_when_in_scope" } } }
});

/** @param {readonly number[]} samples @param {number} ratio */
function percentile(samples, ratio) {
  const sorted = [...samples].sort((left, right) => left - right);
  return sorted[Math.min(sorted.length - 1, Math.floor((sorted.length - 1) * ratio))] ?? 0;
}

/** @param {readonly number[]} samples */
function distribution(samples) {
  return { p50Ms: Number(percentile(samples, 0.5).toFixed(3)), p95Ms: Number(percentile(samples, 0.95).toFixed(3)), maxMs: Number(Math.max(...samples).toFixed(3)) };
}

/** @param {(index: number) => Promise<unknown> | unknown} operation @param {number} count */
async function measure(operation, count) {
  const samples = [];
  for (let index = 0; index < count; index += 1) {
    const started = performance.now();
    await operation(index);
    samples.push(performance.now() - started);
  }
  return samples;
}

try {
  const deterministic = await measure((index) => evaluateDeterministic("read_project_file", { path: index % 2 === 0 ? "src/index.ts" : "../../.ssh/id_rsa" }, config), iterations);
  const outputInspection = await measure((index) => Promise.resolve(inspectToolResult({ content: [{ type: "text", text: index % 2 === 0 ? "ordinary benchmark output" : `OPENAI_API_KEY=${"sk"}-proj-BENCHMARK_NOT_A_SECRET_000000` }] }, config)), iterations);
  const audit = new AuditLog(path.join(temporary, "audit"), "benchmark-session");
  const auditWrite = await measure((index) => audit.append("benchmark", { index, toolName: "read_project_file", args: { sentinel: "not-retained" } }), iterations);
  await audit.close();
  const cache = new ExactCallCache();
  const cacheKey = cache.fingerprint({ targetName: "benchmark", toolName: "read_project_file", schemaHash: "schema", policyHash: "policy", args: { path: "src/index.ts" }, mode: "interactive" });
  cache.set(cacheKey, "cached", 60);
  const cacheLookup = await measure(() => Promise.resolve(cache.get(cacheKey)), iterations);
  const concurrentStarted = performance.now();
  await Promise.all(Array.from({ length: 20 }, (_value, index) => evaluateDeterministic("read_project_file", { path: index % 2 === 0 ? "src/index.ts" : "../../.ssh/id_rsa" }, config)));
  const concurrentElapsedMs = performance.now() - concurrentStarted;
  process.stdout.write(`${JSON.stringify({
    mode: "local-microbenchmark",
    iterations,
    deterministicDecision: distribution(deterministic),
    outputInspection: distribution(outputInspection),
    auditWrite: distribution(auditWrite),
    cacheLookup: distribution(cacheLookup),
    cache: { hits: cache.hits, misses: cache.misses },
    concurrentDeterministicCalls: { calls: 20, elapsedMs: Number(concurrentElapsedMs.toFixed(3)), throughputPerSecond: Number((20_000 / concurrentElapsedMs).toFixed(2)) },
    memoryGrowthBytes: process.memoryUsage().rss - rssBefore,
    limitations: ["This is a local microbenchmark and excludes target-process, network, browser, Docker, and GPT latency.", "Results are intentionally not committed to snapshot artifacts."]
  }, null, 2)}\n`);
} finally {
  await rm(temporary, { recursive: true, force: true });
}
