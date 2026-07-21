/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-return */
import { execFileSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const root = process.cwd();
const args = process.argv.slice(2);
function option(name, fallback) {
  const index = args.indexOf(name);
  return index === -1 ? fallback : args[index + 1];
}
const commit = option("--commit", execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim());
const tag = option("--tag");
const outputPath = option("--output", path.join(root, "release", "verification-status.json"));
if (!/^[a-f0-9]{40}$/.test(commit)) throw new Error("--commit must be a full lowercase Git commit hash");
if (tag === undefined || !/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(tag)) throw new Error("--tag must be a semantic release tag such as v0.1.4");

const actualCommit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
if (actualCommit !== commit) throw new Error(`Checked-out commit ${actualCommit} does not match requested evidence commit ${commit}`);
const tree = execFileSync("git", ["status", "--porcelain"], { cwd: root, encoding: "utf8" }).trim();
if (tree.length !== 0) throw new Error("Release evidence requires a clean working tree");
const taggedCommit = execFileSync("git", ["rev-list", "-n", "1", tag], { cwd: root, encoding: "utf8" }).trim();
if (taggedCommit !== commit) throw new Error(`Release tag ${tag} does not point to ${commit}`);

const rootPackage = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
const version = rootPackage.version;
if (typeof version !== "string" || tag !== `v${version}`) throw new Error(`Release tag ${tag} does not match package version ${String(version)}`);
const workspaceDirectories = ["apps", "packages", "examples"];
for (const directory of workspaceDirectories) {
  const entries = await (await import("node:fs/promises")).readdir(path.join(root, directory), { withFileTypes: true });
  for (const entry of entries.filter((candidate) => candidate.isDirectory())) {
    try {
      const packageJson = JSON.parse(await readFile(path.join(root, directory, entry.name, "package.json"), "utf8"));
      if (packageJson.private !== true && packageJson.version !== version) throw new Error(`${directory}/${entry.name} is version ${String(packageJson.version)}, expected ${version}`);
    } catch (error) {
      if (error instanceof SyntaxError) throw new Error(`Invalid package metadata under ${directory}/${entry.name}`);
      if (error instanceof Error && !error.message.includes("ENOENT")) throw error;
    }
  }
}

const summary = JSON.parse(await readFile(path.join(root, "docs", "verification-summary.json"), "utf8"));
if (summary.releaseTag !== tag || summary.releaseCandidate !== version) throw new Error("Committed verification summary does not match the release tag and version");
if (!Array.isArray(summary.commands) || summary.commands.length === 0 || summary.commands.some((item) => typeof item.command !== "string" || !Number.isInteger(item.exitCode) || !["passed", "failed"].includes(item.status))) throw new Error("Verification summary contains an invalid command record");
const proofPath = path.join(root, "reports", "live-judge-proof.json");
const proof = JSON.parse(await readFile(proofPath, "utf8"));
if (proof.version !== 1 || proof.responseStorage !== false || typeof proof.provider !== "string" || typeof proof.model !== "string" || !Array.isArray(proof.subchecks) || proof.subchecks.length !== 3 || proof.subchecks.some((item) => item.verdict === "unavailable")) {
  throw new Error("Latest live judge proof is missing, malformed, replayed, or contains unavailable subchecks");
}

const status = {
  schemaVersion: 1,
  releaseTag: tag,
  commit,
  checkedAt: new Date().toISOString(),
  version,
  workingTreeClean: true,
  commands: summary.commands,
  chronology: summary.chronology ?? [],
  latestProof: { path: "reports/live-judge-proof.json", valid: true, notQualityClaim: true, provider: proof.provider, model: proof.model }
};
await mkdir(path.dirname(outputPath), { recursive: true });
await writeFile(outputPath, `${JSON.stringify(status, null, 2)}\n`, "utf8");
process.stdout.write(`${JSON.stringify({ outputPath, releaseTag: tag, commit, version, latestProof: status.latestProof }, null, 2)}\n`);
