import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const productDescription = "ToolBastion is a security gateway and evidence layer for mediated MCP calls, with optional target-process containment.";

describe("product-scope documentation", () => {
  it("pins the bounded product description and rejects overclaims", async () => {
    const documents = await Promise.all(["README.md", "SECURITY_ASSUMPTIONS.md"].map(async (file) => ({ file, content: await readFile(path.join(root, file), "utf8") })));
    const overclaims = [/full\s+(?:os\s+)?sandbox/i, /universal\s+firewall/i, /protect(?:s|ion)?\s+(?:against\s+)?unmediated/i];
    for (const document of documents) {
      expect(document.content, `${document.file} must contain the canonical bounded description`).toContain(productDescription);
      for (const overclaim of overclaims) expect(document.content, `${document.file} contains an unsupported scope claim: ${overclaim}`).not.toMatch(overclaim);
    }
  });
});
