/**
 * server/mig/ms5/escape-route-analyzer.ts
 *
 * Escape Route Analysis Engine — models every MCP capability as a node and
 * every allowed invocation chain as a directed edge. Runs graph traversal to
 * discover all paths that terminate in ADMIN, DEPLOY, DANGEROUS, or
 * shell-adjacent capabilities.
 *
 * Produces the three canonical escape paths:
 *   - shortest      — fewest hops to a privileged terminus
 *   - highest_risk  — max cumulative risk score
 *   - most_likely   — highest likelihood product across edges
 */

import { ALL_MCP_TOOLS } from "../../mcp/bripe-mcp-tools";
import { classifyTool } from "@shared/ms5-capability-classification";
import type {
  MS5EscapeRouteAnalysis,
  EscapeRouteNode,
  EscapeRouteEdge,
  EscapeRoutePath,
} from "@shared/ms5-contracts";
import { randomBytes } from "crypto";

const PRIVILEGED_CLASSES = new Set(["ADMIN", "DEPLOY", "DANGEROUS"]);
const PRIVILEGED_MCP_CLASSES = new Set(["admin"]);

const TOOL_RISK_WEIGHTS: Record<string, number> = {
  run_bripe_decision: 0.7,
  start_autopilot_objective: 0.95,
  ingest_replay_record: 0.6,
  ingest_calibra_record: 0.6,
  run_safemerge_forecast: 0.65,
  validate_domain_package: 0.3,
  list_capabilities: 0.1,
  list_domains: 0.1,
  get_bripe_output_manifest: 0.4,
};

const STATIC_CAPABILITY_CHAINS: Array<[string, string, string]> = [
  ["list_domains", "get_domain_package", "domain_enumeration"],
  ["list_capabilities", "get_capability_contract", "capability_discovery"],
  ["get_capability_contract", "run_bripe_decision", "execution_chain"],
  ["list_domains", "start_autopilot_objective", "domain_to_admin"],
  ["list_capabilities", "start_autopilot_objective", "discovery_to_admin"],
  ["run_bripe_decision", "ingest_replay_record", "decision_to_write"],
  ["run_bripe_decision", "ingest_calibra_record", "decision_to_calibra"],
  ["get_bripe_output_manifest", "run_bripe_decision", "manifest_to_execution"],
  ["list_bripe_layers", "run_bripe_decision", "layer_to_execution"],
  ["retrieve_adaptation_memories", "ingest_replay_record", "memory_to_write"],
  ["list_active_odps", "start_autopilot_objective", "odp_to_admin"],
  ["validate_domain_package", "start_autopilot_objective", "validate_to_admin"],
];

/**
 * Derive edges dynamically from the manifest of registered MCP tools.
 * Rules derived from classification:
 *  - Every read_only tool can escalate to every execution tool (read→exec path)
 *  - Every execution tool can escalate to every admin tool (exec→admin path)
 * This supplements the static chains with live manifest visibility so new
 * tools automatically appear in the attack graph without manual updates.
 */
function buildManifestEdges(allTools: typeof ALL_MCP_TOOLS): Array<[string, string, string]> {
  const readOnly = allTools.filter(t => t.classification === "read_only").map(t => t.name);
  const execution = allTools.filter(t => t.classification === "execution").map(t => t.name);
  const admin = allTools.filter(t => t.classification === "admin").map(t => t.name);

  const edges: Array<[string, string, string]> = [];

  for (const ro of readOnly) {
    for (const ex of execution) {
      edges.push([ro, ex, `manifest_read_to_exec`]);
    }
  }
  for (const ex of execution) {
    for (const adm of admin) {
      edges.push([ex, adm, `manifest_exec_to_admin`]);
    }
  }

  return edges;
}

function buildCapabilityChains(allTools: typeof ALL_MCP_TOOLS): Array<[string, string, string]> {
  const manifest = buildManifestEdges(allTools);
  const combined = [...STATIC_CAPABILITY_CHAINS];
  const existing = new Set(STATIC_CAPABILITY_CHAINS.map(([f, t]) => `${f}::${t}`));
  for (const edge of manifest) {
    if (!existing.has(`${edge[0]}::${edge[1]}`)) {
      combined.push(edge);
    }
  }
  return combined;
}

function nodeId(toolName: string): string {
  return `node_${toolName}`;
}

function toolRiskWeight(toolName: string, classification: string): number {
  if (TOOL_RISK_WEIGHTS[toolName]) return TOOL_RISK_WEIGHTS[toolName];
  if (classification === "admin") return 0.9;
  if (classification === "execution") return 0.6;
  return 0.2;
}

function layoutNodes(nodes: EscapeRouteNode[]): EscapeRouteNode[] {
  const cols: Record<string, number> = { read_only: 0, execution: 1, admin: 2 };
  const colCounts: Record<number, number> = { 0: 0, 1: 0, 2: 0 };
  return nodes.map(n => {
    const col = cols[n.privilege_level] ?? 0;
    const row = colCounts[col] ?? 0;
    colCounts[col] = row + 1;
    return { ...n, x: col * 200 + 80, y: row * 80 + 60 };
  });
}

export function runEscapeRouteAnalysis(): MS5EscapeRouteAnalysis {
  const allTools = ALL_MCP_TOOLS;

  const nodes: EscapeRouteNode[] = allTools.map(t => ({
    id: nodeId(t.name),
    capability_name: t.name,
    classification: t.classification,
    ms5_class: classifyTool(t.name),
    privilege_level: t.classification,
  }));

  const capabilityChains = buildCapabilityChains(allTools);
  const edges: EscapeRouteEdge[] = capabilityChains.map(([from, to, label]) => ({
    from: nodeId(from),
    to: nodeId(to),
    label,
    risk_weight: toolRiskWeight(to, allTools.find(t => t.name === to)?.classification ?? "read_only"),
  }));

  const privilegedNodeIds = new Set(
    allTools
      .filter(t => PRIVILEGED_CLASSES.has(classifyTool(t.name)) || PRIVILEGED_MCP_CLASSES.has(t.classification))
      .map(t => nodeId(t.name))
  );

  type PathState = { nodes: string[]; risk: number; likelihood: number };

  const allPaths: PathState[] = [];

  function dfs(current: string, path: string[], visited: Set<string>, risk: number, likelihood: number) {
    if (visited.has(current)) return;
    if (path.length > 6) return;

    const newPath = [...path, current];
    const newVisited = new Set([...visited, current]);

    if (privilegedNodeIds.has(current) && path.length > 0) {
      allPaths.push({ nodes: newPath, risk, likelihood });
    }

    const outEdges = edges.filter(e => e.from === current);
    for (const edge of outEdges) {
      dfs(edge.to, newPath, newVisited, risk + edge.risk_weight, likelihood * edge.risk_weight);
    }
  }

  const startNodes = allTools
    .filter(t => t.classification === "read_only")
    .map(t => nodeId(t.name));

  for (const start of startNodes) {
    dfs(start, [], new Set(), 0, 1.0);
  }

  if (allPaths.length === 0) {
    const adminNodes = allTools
      .filter(t => t.classification === "admin" || classifyTool(t.name) === "DANGEROUS")
      .map(t => nodeId(t.name));

    for (const n of adminNodes) {
      const reachEdges = edges.filter(e => e.to === n);
      for (const edge of reachEdges) {
        allPaths.push({
          nodes: [edge.from, edge.to],
          risk: edge.risk_weight,
          likelihood: edge.risk_weight,
        });
      }
    }
  }

  function buildPathEdges(pathNodes: string[]): EscapeRouteEdge[] {
    const result: EscapeRouteEdge[] = [];
    for (let i = 0; i < pathNodes.length - 1; i++) {
      const edge = edges.find(e => e.from === pathNodes[i] && e.to === pathNodes[i + 1]);
      if (edge) result.push(edge);
    }
    return result;
  }

  const canonicalPaths: EscapeRoutePath[] = [];

  if (allPaths.length > 0) {
    const shortest = allPaths.reduce((a, b) => a.nodes.length <= b.nodes.length ? a : b);
    const highestRisk = allPaths.reduce((a, b) => a.risk >= b.risk ? a : b);
    const mostLikely = allPaths.reduce((a, b) => a.likelihood >= b.likelihood ? a : b);

    const addPath = (p: PathState, type: "shortest" | "highest_risk" | "most_likely") => {
      const terminus = p.nodes[p.nodes.length - 1];
      const terminusTool = allTools.find(t => nodeId(t.name) === terminus);
      canonicalPaths.push({
        path_id: `path_${randomBytes(4).toString("hex")}`,
        nodes: p.nodes,
        edges: buildPathEdges(p.nodes),
        path_length: p.nodes.length,
        cumulative_risk_score: Math.round(p.risk * 100) / 100,
        likelihood_score: Math.round(p.likelihood * 1000) / 1000,
        terminates_at: terminusTool?.name ?? terminus,
        path_type: type,
      });
    };

    // Always emit all three canonical path types — even if they resolve to the
    // same underlying path, each type carries independent semantic meaning.
    addPath(shortest, "shortest");
    addPath(highestRisk, "highest_risk");
    addPath(mostLikely, "most_likely");
  }

  const laidOutNodes = layoutNodes(nodes);

  const highestRiskTerminus = canonicalPaths.length > 0
    ? canonicalPaths.find(p => p.path_type === "highest_risk")?.terminates_at ??
      canonicalPaths[0].terminates_at
    : "start_autopilot_objective";

  return {
    nodes: laidOutNodes,
    edges,
    canonical_paths: canonicalPaths,
    total_paths_discovered: allPaths.length,
    highest_risk_terminus: highestRiskTerminus,
  };
}
