#!/usr/bin/env node
// Measure advertised MCP tool payload costs per family through the real
// EvidenceMcpServer advertisement path (compact transform, family scoping,
// output-schema omission), then report byte totals with token estimates.
//
// Methodology mirrors discussion #3098: count the compact JSON of each tool's
// name, description, and input schema — exactly what a full-send client
// receives per tool. Token figures are estimates: a chars/4 heuristic plus a
// calibration against the published #3098 full-catalog total (193,578 tokens
// for 206 tools). Byte totals are exact; token columns are labeled estimates.
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { STDIO_DEFAULT_MAX_BUFFER_SIZE } from "@modelcontextprotocol/server";

import { TOOL_CONTRACTS } from "../dist/contracts/toolContracts.js";
import {
  TOOL_FAMILY_IDS,
  toolFamilyId,
} from "../dist/contracts/toolFamilies.js";
import { COMPACT_INPUT_SCHEMA_BUDGET_BYTES } from "../dist/config/mcpInputSchemaProfile.js";
import { EvidenceMcpServer } from "../dist/server/EvidenceMcpServer.js";
import { ToolResultDelivery } from "../dist/server/toolResult.js";
import { toolRegistrationOptions } from "../dist/server/toolRegistrationOptions.js";

// Published reference totals from discussion #3098 (model-tokenizer counts).
const REFERENCE_FULL_TOKENS = 193578;
const REFERENCE_FULL_COUNT = 206;
const REFERENCE_COMPACT_TOKENS = 79788;
const REFERENCE_SESSION_COMPACT_TOKENS = 15489;

const listAdvertised = async ({ families, compact, omitOutputSchemas }) => {
  const server = new EvidenceMcpServer(
    { name: "tool-token-measure", version: "0" },
    { capabilities: {} },
    undefined,
    new ToolResultDelivery(STDIO_DEFAULT_MAX_BUFFER_SIZE),
    compact ? { budgetBytes: COMPACT_INPUT_SCHEMA_BUDGET_BYTES } : undefined,
    omitOutputSchemas,
    families === undefined ? undefined : new Set(families),
  );
  for (const contract of TOOL_CONTRACTS)
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      async () => ({ content: [] }),
    );
  const client = new Client({ name: "tool-token-measure", version: "0" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    return (await client.listTools()).tools;
  } finally {
    await Promise.allSettled([client.close(), server.close()]);
  }
};

const payloadBytes = (tool) =>
  Buffer.byteLength(
    JSON.stringify({
      name: tool.name,
      description: tool.description,
      inputSchema: tool.inputSchema,
    }),
    "utf8",
  );

const outputBytes = (tool) =>
  tool.outputSchema === undefined
    ? 0
    : Buffer.byteLength(JSON.stringify(tool.outputSchema), "utf8");

const summarize = (tools) => {
  const rows = tools.map((tool) => ({
    name: tool.name,
    family: toolFamilyId(tool.name) ?? "(ungrouped)",
    bytes: payloadBytes(tool),
    outputBytes: outputBytes(tool),
  }));
  const bytes = rows.reduce((sum, row) => sum + row.bytes, 0);
  const outputBytesTotal = rows.reduce((sum, row) => sum + row.outputBytes, 0);
  return { rows, bytes, outputBytesTotal, count: rows.length };
};

const full = summarize(await listAdvertised({}));
const bytesPerReferenceToken = full.bytes / REFERENCE_FULL_TOKENS;
const estimate = (bytes) => Math.round(bytes / bytesPerReferenceToken);
const heuristic = (bytes) => Math.round(bytes / 4);

const line = (cells) => `| ${cells.join(" | ")} |`;
const rows = [];
rows.push("# MCP tool advertisement cost");
rows.push("");
rows.push(
  `Measured through EvidenceMcpServer tools/list on ${full.count} registered tools ` +
    `(reference #3098 counted ${REFERENCE_FULL_COUNT}). Byte totals are exact; ` +
    "token columns are estimates calibrated at " +
    `${bytesPerReferenceToken.toFixed(2)} bytes/token against the published full-catalog total. ` +
    `Output schemas are dense JSON with fewer chars per token than mixed prose, ` +
    `so calibrated totals that include output bytes are lower bounds.`,
);
rows.push("");
rows.push(
  line([
    "Scope",
    "Profile",
    "Output schemas",
    "Tools",
    "Bytes in+out",
    "~Tokens (calibrated)",
    "~Tokens (chars/4)",
  ]),
);
rows.push(line(["---", "---", "---", "--:", "--:", "--:", "--:"]));

const scenarios = [
  ["full", undefined, false, false],
  ["full", undefined, true, false],
  ["full", undefined, true, true],
  ["session", ["session"], false, false],
  ["session", ["session"], true, false],
  ["session", ["session"], true, true],
  ["session,direct", ["session", "direct"], true, false],
  ["session,direct", ["session", "direct"], true, true],
];
const byKey = new Map();
for (const [label, families, compact, omitOutput] of scenarios) {
  const key = `${label}/${compact ? "compact" : "full"}/${omitOutput ? "omit" : "keep"}`;
  if (byKey.has(key)) continue;
  const summary = summarize(
    await listAdvertised({ families, compact, omitOutputSchemas: omitOutput }),
  );
  byKey.set(key, summary);
  const total = summary.bytes + summary.outputBytesTotal;
  rows.push(
    line([
      label,
      compact ? "compact" : "full",
      omitOutput ? "omitted" : "sent",
      String(summary.count),
      String(total),
      String(estimate(total)),
      String(heuristic(total)),
    ]),
  );
}
rows.push("");
rows.push("## Sanity check against #3098");
rows.push("");
const compactTotal = byKey.get("full/compact/keep").bytes;
const sessionCompact = byKey.get("session/compact/keep").bytes;
rows.push(
  `- Full compact: estimated ${estimate(compactTotal)} vs published ${REFERENCE_COMPACT_TOKENS} ` +
    `(delta ${estimate(compactTotal) - REFERENCE_COMPACT_TOKENS}).`,
);
rows.push(
  `- Session compact: estimated ${estimate(sessionCompact)} vs published ${REFERENCE_SESSION_COMPACT_TOKENS} ` +
    `(delta ${estimate(sessionCompact) - REFERENCE_SESSION_COMPACT_TOKENS}).`,
);
rows.push(
  "- Deltas come from catalog drift since the benchmark head plus heuristic vocabulary differences; " +
    "byte totals are the exact comparator.",
);
rows.push("");
rows.push("## Per-family cost (compact profile)");
rows.push("");
rows.push(line(["Family", "Tools", "Bytes", "~Tokens (calibrated)"]));
rows.push(line(["---", "--:", "--:", "--:"]));
for (const id of TOOL_FAMILY_IDS) {
  const summary = summarize(
    await listAdvertised({
      families: [id],
      compact: true,
      omitOutputSchemas: false,
    }),
  );
  if (summary.count === 0) continue;
  rows.push(
    line([
      id,
      String(summary.count),
      String(summary.bytes),
      String(estimate(summary.bytes)),
    ]),
  );
}
rows.push("");
rows.push("## Fattest advertised tools (compact profile, input side)");
rows.push("");
rows.push(line(["Tool", "Family", "Bytes", "~Tokens (calibrated)"]));
rows.push(line(["---", "---", "--:", "--:"]));
const compactTools = await listAdvertised({
  families: undefined,
  compact: true,
  omitOutputSchemas: false,
});
summarize(compactTools)
  .rows.sort((left, right) => right.bytes - left.bytes)
  .slice(0, 20)
  .forEach((row) =>
    rows.push(
      line([
        row.name,
        row.family,
        String(row.bytes),
        String(estimate(row.bytes)),
      ]),
    ),
  );
rows.push("");
rows.push("## Output schemas (full catalog, for the output-profile story)");
rows.push("");
const outputTotal = summarize(compactTools).rows.reduce(
  (sum, row) => sum + row.outputBytes,
  0,
);
rows.push(
  `Total outputSchema bytes across all advertised tools: ${outputTotal} (~${estimate(outputTotal)} calibrated tokens).`,
);
rows.push("");
rows.push(line(["Tool", "Output bytes"]));
rows.push(line(["---", "--:"]));
summarize(compactTools)
  .rows.sort((left, right) => right.outputBytes - left.outputBytes)
  .slice(0, 10)
  .forEach((row) => rows.push(line([row.name, String(row.outputBytes)])));
rows.push("");

console.log(rows.join("\n"));
