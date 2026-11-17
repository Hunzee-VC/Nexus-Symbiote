// Exercise the WasmAgent agentbom-core library on a hand-written AgentBOM document for the
// fixture agent: validate, run a compliance check, then diff against a changed copy.
// The library discovers nothing; this only records whether its documented functions work.
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const out = process.argv[2] || ".";
// Resolve the package from the working directory (the npm install root), not from this file.
const core = await import(pathToFileURL(join(process.cwd(), "node_modules/@wasmagent/agentbom-core/dist/index.js")).href);

const baseline = {
  agentbom_version: "0.1",
  identity: {
    agent_id: "support-triage-agent",
    agent_name: "Acme Support Agent",
    generated_at: "2026-11-17T00:00:00Z",
  },
  attestation: { generator: "aab-benchmark" },
};
const toolShapes = [
  [{ tool_id: "delete_ticket", tool_name: "delete_ticket", source: "mcp:tickets", permissions: ["tickets:write"] }],
  [{ tool_id: "delete_ticket", tool_name: "delete_ticket", source: "mcp:tickets" }],
  [{ tool_id: "delete_ticket", source: "mcp:tickets" }],
];
let withTools = null;
const shapeReport = [];
for (const tools of toolShapes) {
  const doc = { ...baseline, tools };
  const v = core.validateAgentBOM(doc);
  shapeReport.push({ tools, valid: v.valid, errors: v.errors });
  if (v.valid && !withTools) withTools = doc;
}
const validation = core.validateAgentBOM(withTools || baseline);
// The README documents checkCompliance(doc, { require_signed, max_tool_count, disallowed_scopes }).
// Record whether that call works, and fall back to a minimal profile object if it does not.
let compliance = null;
const complianceAttempts = [];
for (const profile of [
  { require_signed: true, max_tool_count: 20, disallowed_scopes: ["filesystem:write"] },
  { rules: { identity: {}, tools: {}, attestation: {}, model_dependencies: {}, permissions: {} } },
  { rules: { identity: { require_signed: true }, tools: { max_tool_count: 20, disallowed_scopes: ["filesystem:write"] } } },
]) {
  try {
    compliance = core.checkCompliance(withTools || baseline, profile);
    complianceAttempts.push({ profile, ok: true });
    break;
  } catch (err) {
    complianceAttempts.push({ profile, ok: false, error: String(err).slice(0, 200) });
  }
}
const changed = JSON.parse(JSON.stringify(withTools || baseline));
changed.identity.generated_at = "2026-11-18T00:00:00Z";
changed.identity.agent_name = "Acme Support Agent v2";
if (changed.tools) changed.tools.push({ ...changed.tools[0], tool_id: "export_customers", tool_name: "export_customers" });
const diff = core.diffAgentBOM(withTools || baseline, changed);
// The README documents buildDriftAlert(agentId, diff, baselineTs, currentTs); 0.4.0 exports
// createDriftAlert(partial) instead. Record what works.
let alert = null;
let driftError = null;
try {
  const events = core.classifyDriftEvents ? core.classifyDriftEvents(diff) : [];
  alert = core.createDriftAlert({ agent_id: "support-triage-agent", events, diff, baseline_generated_at: baseline.identity.generated_at, current_generated_at: changed.identity.generated_at });
} catch (err) {
  driftError = String(err).slice(0, 200);
}
let driftText = null;
try {
  driftText = alert && core.formatDriftAlert ? core.formatDriftAlert(alert) : null;
} catch (err) {
  driftError = (driftError ? driftError + "; " : "") + String(err).slice(0, 200);
}
const report = {
  readme_api_present: { buildDriftAlert: typeof core.buildDriftAlert === "function" },
  drift_error: driftError,
  exports: Object.keys(core).sort(),
  supported_versions: core.getSupportedVersions(),
  tool_shape_probe: shapeReport,
  validation,
  compliance_attempts: complianceAttempts,
  compliance,
  diff,
  drift_alert_text: driftText,
};
writeFileSync(join(out, "library-check.json"), JSON.stringify(report, null, 2) + "\n");
console.log(JSON.stringify({ valid: validation.valid, compliance_ran: compliance !== null, compliance_passed: compliance ? compliance.passed : null, compliance_findings: compliance ? (compliance.findings || []).length : null, diff_keys: Object.keys(diff || {}) }, null, 2));
