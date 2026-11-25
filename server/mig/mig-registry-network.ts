import { lookup } from "dns/promises";
import { lookup as lookupPinnedAddress } from "node:dns";
import { isIP } from "net";
import { Agent } from "undici";
import { gunzipSync } from "node:zlib";

const MAX_TARGET_LENGTH = 2048;
const MAX_RESPONSE_BYTES = 1_000_000;
const MAX_REGISTRY_ENTRIES = 100;

const ipv4Number = (address: string) => address.split(".").reduce((n, part) => (n * 256) + Number(part), 0) >>> 0;
const privateAddress = (address: string): boolean => {
  if (isIP(address) === 4) {
    const [a, b] = address.split(".").map(Number);
    return a === 10 || a === 127 || a === 0 || a >= 224 || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  const value = address.toLowerCase();
  return value === "::1" || value === "::" || value.startsWith("fe8") || value.startsWith("fe9") ||
    value.startsWith("fea") || value.startsWith("feb") || value.startsWith("fc") || value.startsWith("fd") ||
    value.startsWith("::ffff:127.") || value.startsWith("2001:db8:");
};

function inCidr(address: string, cidr: string): boolean {
  const [network, bitsText] = cidr.split("/");
  if (isIP(address) !== 4 || isIP(network) !== 4) return address === network;
  const bits = Number(bitsText);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipv4Number(address) & mask) === (ipv4Number(network) & mask);
}

export function matchesNetworkConstraint(rawAddress: string, constraint: string): boolean {
  const address = rawAddress.startsWith("::ffff:") ? rawAddress.slice(7) : rawAddress;
  if (constraint.includes("/")) return inCidr(address, constraint);
  if (/^[0-9.]+-[0-9.]+$/.test(constraint)) {
    const [from, to] = constraint.split("-");
    return isIP(address) === 4 && isIP(from) === 4 && isIP(to) === 4 &&
      ipv4Number(address) >= ipv4Number(from) && ipv4Number(address) <= ipv4Number(to);
  }
  return address === constraint;
}

export function selectPreauthorizedScopes(requested: unknown, configured: string[]): string[] {
  const scopes = Array.isArray(requested) ? requested.filter((value): value is string => typeof value === "string" && !!value) : [];
  if (!scopes.length || scopes.some(scope => !configured.includes(scope))) throw new Error("MIG_NETWORK_SCOPE_NOT_PREAUTHORIZED");
  return [...new Set(scopes)];
}

function matchesScope(target: URL, address: string, rawScope: string): boolean {
  const scope = rawScope.trim();
  if (!scope) return false;
  if (scope.startsWith("segment:")) return false; // segment membership needs adapter-supplied evidence
  if (scope.includes("/") && !scope.includes("://")) return inCidr(address, scope);
  if (/^[0-9.]+-[0-9.]+$/.test(scope)) {
    const [from, to] = scope.split("-");
    return isIP(address) === 4 && isIP(from) === 4 && isIP(to) === 4 &&
      ipv4Number(address) >= ipv4Number(from) && ipv4Number(address) <= ipv4Number(to);
  }
  if (!scope.includes("://")) {
    const host = scope.replace(/^\*\./, "").toLowerCase();
    return target.hostname.toLowerCase() === host || (scope.startsWith("*.") && target.hostname.toLowerCase().endsWith(`.${host}`));
  }
  let approved: URL;
  try { approved = new URL(scope); } catch { return false; }
  if (approved.protocol !== target.protocol || approved.hostname !== target.hostname ||
      (approved.port || "") !== (target.port || "")) return false;
  const approvedPath = approved.pathname.endsWith("/") ? approved.pathname : `${approved.pathname}/`;
  return target.pathname === approved.pathname || target.pathname.startsWith(approvedPath);
}

export interface ValidatedRegistryTarget { url: string; origin: string; addresses: string[]; }

export async function validateRegistryTarget(
  raw: unknown, scopes: string[], mode: "approved_network" | "api",
  resolve: (host: string) => Promise<{ address: string }[]> = host => lookup(host, { all: true }),
): Promise<ValidatedRegistryTarget> {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > MAX_TARGET_LENGTH) throw new Error("MIG_REGISTRY_TARGET_INVALID");
  let target: URL;
  try { target = new URL(raw); } catch { throw new Error("MIG_REGISTRY_TARGET_INVALID"); }
  if (!["http:", "https:"].includes(target.protocol) || target.username || target.password || target.hash) throw new Error("MIG_REGISTRY_TARGET_SCHEME_INVALID");
  const addresses = (await resolve(target.hostname)).map(answer => answer.address);
  if (!addresses.length || addresses.length > 16 || addresses.some(address => !isIP(address))) throw new Error("MIG_REGISTRY_DNS_INVALID");
  if (!Array.isArray(scopes) || scopes.length === 0 || !addresses.every(address => scopes.some(scope => matchesScope(target, address, scope)))) {
    throw new Error("MIG_REGISTRY_SCOPE_ESCAPE");
  }
  const privateTargets = addresses.filter(privateAddress);
  if (mode === "api" && privateTargets.length) throw new Error("MIG_REGISTRY_API_NONPUBLIC_TARGET");
  if (mode === "approved_network" && privateTargets.length &&
      !scopes.some(scope => scope === target.hostname || scope === target.origin || scope === `${target.origin}/` ||
        (!scope.includes("://") && privateTargets.every(address => matchesScope(target, address, scope))))) {
    throw new Error("MIG_REGISTRY_PRIVATE_TARGET_NOT_EXACTLY_APPROVED");
  }
  return { url: target.toString(), origin: target.origin, addresses: [...new Set(addresses)].sort() };
}

async function boundedFetch(url: string, addresses: string[], init: RequestInit, timeoutMs = 5_000): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.min(Math.max(timeoutMs, 250), 10_000));
  const address = addresses[0];
  const dispatcher = new Agent({ connect: { lookup: (_hostname, _options, callback) =>
    lookupPinnedAddress(address, _options, callback) } });
  try { return await fetch(url, { ...init, redirect: "manual", signal: controller.signal, dispatcher } as RequestInit); }
  finally { clearTimeout(timer); }
}

async function readBounded(response: Response): Promise<string> {
  const declared = Number(response.headers.get("content-length") ?? 0);
  if (declared > MAX_RESPONSE_BYTES) throw new Error("MIG_REGISTRY_RESPONSE_TOO_LARGE");
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") > MAX_RESPONSE_BYTES) throw new Error("MIG_REGISTRY_RESPONSE_TOO_LARGE");
  return text;
}

function parseMcpPayload(body: string): any {
  try { return JSON.parse(body); } catch {
    // Streamable HTTP MCP servers may encode JSON-RPC responses as SSE.
    const frames = body.split(/\r?\n\r?\n/).map(frame => frame.split(/\r?\n/)
      .filter(line => line.startsWith("data:")).map(line => line.slice(5).trim()).join("\n")).filter(Boolean);
    for (const frame of frames.reverse()) {
      try { return JSON.parse(frame); } catch { /* try earlier event */ }
    }
    throw new Error("MIG_MCP_RESPONSE_INVALID");
  }
}

async function verifiedMcpPost(raw: string, scopes: string[], mode: "approved_network" | "api", body: object, headers: Record<string, string> = {}, allowEmpty = false) {
  const before = await validateRegistryTarget(raw, scopes, mode);
  const response = await boundedFetch(before.url, before.addresses, {
    method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers },
    body: JSON.stringify(body),
  });
  if (response.status >= 300 && response.status < 400) throw new Error("MIG_REGISTRY_REDIRECT_FORBIDDEN");
  if (!response.ok) throw new Error(`MIG_MCP_UNREACHABLE_${response.status}`);
  const text = await readBounded(response);
  const after = await validateRegistryTarget(before.url, scopes, mode);
  if (before.addresses.join(",") !== after.addresses.join(",")) throw new Error("MIG_REGISTRY_DNS_REBINDING");
  return { payload: text ? parseMcpPayload(text) : (allowEmpty ? {} : (() => { throw new Error("MIG_MCP_RESPONSE_INVALID"); })()), sessionId: response.headers.get("mcp-session-id") ?? undefined, addresses: before.addresses };
}

export const MIG_MCP_PROTOCOL_PREFERENCES = ["2025-03-26", "2024-11-05", "2024-10-07"] as const;

export async function probeMcpEndpoint(raw: string, scopes: string[], mode: "approved_network" | "api" = "approved_network") {
  let initialize: Awaited<ReturnType<typeof verifiedMcpPost>> | null = null;
  let result: any = null;
  for (const protocolVersion of MIG_MCP_PROTOCOL_PREFERENCES) {
    try {
      const candidate = await verifiedMcpPost(raw, scopes, mode, {
        jsonrpc: "2.0", id: "mig-onboarding", method: "initialize",
        params: { protocolVersion, capabilities: {}, clientInfo: { name: "MIG", version: "1" } },
      });
      const candidateResult = candidate.payload?.result;
      if (
        candidateResult
        && typeof candidateResult.protocolVersion === "string"
        && (MIG_MCP_PROTOCOL_PREFERENCES as readonly string[]).includes(candidateResult.protocolVersion)
      ) {
        initialize = candidate;
        result = candidateResult;
        break;
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const retryableProtocolRejection =
        message === "MIG_MCP_UNREACHABLE_400"
        || message === "MIG_MCP_UNREACHABLE_406";
      if (!retryableProtocolRejection) throw error;
    }
  }
  if (!initialize || !result) throw new Error("MIG_MCP_PROTOCOL_INCOMPATIBLE");
  const sessionHeaders: Record<string, string> = initialize.sessionId
    ? { "mcp-session-id": initialize.sessionId }
    : {};
  // Required MCP lifecycle notification, sent before any tool discovery.
  await verifiedMcpPost(raw, scopes, mode, { jsonrpc: "2.0", method: "notifications/initialized", params: {} }, sessionHeaders, true);
  const toolDeclarations: any[] = [];
  const seenCursors = new Set<string>();
  let cursor: string | undefined;
  do {
    const toolsResponse = await verifiedMcpPost(raw, scopes, mode,
      { jsonrpc: "2.0", id: "mig-tools-list", method: "tools/list", params: cursor ? { cursor } : {} }, sessionHeaders);
    const page = toolsResponse.payload?.result;
    if (toolsResponse.payload?.error || !Array.isArray(page?.tools) ||
        page.tools.some((tool: any) => !tool || typeof tool.name !== "string")) {
      throw new Error("MIG_MCP_TOOLS_RESPONSE_INVALID");
    }
    toolDeclarations.push(...page.tools);
    if (toolDeclarations.length > 1000) throw new Error("MIG_MCP_TOOLS_LIMIT");
    const next = page.nextCursor;
    if (next !== undefined && (typeof next !== "string" || !next || next.length > 2048 || seenCursors.has(next))) {
      throw new Error("MIG_MCP_TOOLS_CURSOR_INVALID");
    }
    if (next !== undefined) seenCursors.add(next);
    if (seenCursors.size > 20) throw new Error("MIG_MCP_TOOLS_LIMIT");
    cursor = next;
  } while (cursor);
  const tools = toolDeclarations.map((tool: any) => tool.name);
  return {
    reachable: true, protocolCompatible: true, resolvedAddresses: initialize.addresses, sessionId: initialize.sessionId,
    protocolVersion: result.protocolVersion,
    serverInfo: result.serverInfo && typeof result.serverInfo === "object" ? result.serverInfo : undefined,
    // Extension declarations are the only accepted source for MIG continuation
    // and terminal-outcome support; callers cannot assert these properties.
    mig: result.capabilities?.mig && typeof result.capabilities.mig === "object" ? result.capabilities.mig : undefined,
    capabilities: tools,
    /** Full endpoint-derived declarations, including schemas and governance metadata. */
    toolDeclarations,
  };
}

/** Delivers a generated credential only to an endpoint that declared a secure
 * MCP extension method. The caller must never persist or log the raw key. */
export async function deliverMcpCredential(raw: string, scopes: string[], sessionId: string | undefined, method: string, apiKey: string) {
  if (!/^[-A-Za-z0-9._/:]{1,128}$/.test(method)) throw new Error("MIG_MCP_CREDENTIAL_METHOD_INVALID");
  const response = await verifiedMcpPost(raw, scopes, "api", {
    jsonrpc: "2.0", id: "mig-credential-bind", method, params: { credential: apiKey },
  }, sessionId ? { "mcp-session-id": sessionId } : {});
  if (!response.payload || response.payload.error || response.payload.result?.accepted !== true) {
    throw new Error("MIG_MCP_CREDENTIAL_DELIVERY_UNACKNOWLEDGED");
  }
}

export async function fetchRegistryEntries(raw: string, scopes: string[], authorization?: string) {
  const before = await validateRegistryTarget(raw, scopes, "api");
  const response = await boundedFetch(before.url, before.addresses, {
    headers: { accept: "application/json", ...(authorization ? { authorization } : {}) },
  });
  if (response.status >= 300 && response.status < 400) throw new Error("MIG_REGISTRY_REDIRECT_FORBIDDEN");
  if (!response.ok) throw new Error(`MIG_REGISTRY_IMPORT_FAILED_${response.status}`);
  const body = await readBounded(response);
  const after = await validateRegistryTarget(before.url, scopes, "api");
  if (before.addresses.join(",") !== after.addresses.join(",")) throw new Error("MIG_REGISTRY_DNS_REBINDING");
  let parsed: unknown;
  try { parsed = JSON.parse(body); } catch { throw new Error("MIG_REGISTRY_RESPONSE_INVALID"); }
  const entries = Array.isArray(parsed) ? parsed : Array.isArray((parsed as any)?.entries) ? (parsed as any).entries : [];
  if (entries.length > MAX_REGISTRY_ENTRIES) throw new Error("MIG_REGISTRY_TOO_MANY_ENTRIES");
  return entries as Array<Record<string, unknown>>;
}

export function validateRedirectTarget(location: string, approvedScopes: string[], mode: "approved_network" | "api") {
  return validateRegistryTarget(location, approvedScopes, mode);
}

/** Bounded, credential-free document read for domain discovery, not MCP execution. */
export async function fetchMigDiscoveryDocument(raw: string, privateScopes: string[] = []): Promise<string> {
  const origin = new URL(raw).origin;
  if (new URL(raw).protocol !== "https:") throw new Error("MIG_DISCOVERY_HTTPS_REQUIRED");
  const controller = new AbortController();
  let dispatcher: Agent | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => { controller.abort(); reject(new Error("MIG_DISCOVERY_DOCUMENT_TIMEOUT")); }, 5000);
  });
  const work = async () => {
    let scopes = [origin];
    let mode: "api" | "approved_network" = "api";
    let before: ValidatedRegistryTarget;
    try { before = await validateRegistryTarget(raw, scopes, mode); }
    catch (error) {
      if (!(error instanceof Error) || error.message !== "MIG_REGISTRY_API_NONPUBLIC_TARGET" || !privateScopes.length) throw error;
      scopes = privateScopes;
      mode = "approved_network";
      before = await validateRegistryTarget(raw, scopes, mode);
    }
    controller.signal.throwIfAborted();
    const address = before.addresses[0];
    dispatcher = new Agent({ connect: { lookup: (_host, options, callback) => lookupPinnedAddress(address, options, callback) } });
    const response = await fetch(before.url, {
      method: "GET", redirect: "manual", signal: controller.signal, dispatcher,
      headers: { accept: "application/xml, text/xml, text/plain", "user-agent": "MIG-DomainDiscovery/1.0" },
    } as RequestInit);
    if (!response.ok) throw new Error(`MIG_DISCOVERY_HTTP_${response.status}`);
    const maxBytes = 512_000;
    if (Number(response.headers.get("content-length") || 0) > maxBytes || !response.body) throw new Error("MIG_DISCOVERY_DOCUMENT_TOO_LARGE_OR_EMPTY");
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let length = 0;
    try {
      while (true) {
        const next = await reader.read();
        if (next.done) break;
        length += next.value.byteLength;
        if (length > maxBytes) throw new Error("MIG_DISCOVERY_DOCUMENT_TOO_LARGE");
        chunks.push(next.value);
      }
    } finally { await reader.cancel().catch(() => {}); }
    const after = await validateRegistryTarget(raw, scopes, mode);
    controller.signal.throwIfAborted();
    if (before.addresses.join(",") !== after.addresses.join(",")) throw new Error("MIG_REGISTRY_DNS_REBINDING");
    const bytes = Buffer.concat(chunks);
    return (bytes[0] === 0x1f && bytes[1] === 0x8b ? gunzipSync(bytes, { maxOutputLength: maxBytes }) : bytes).toString("utf8");
  };
  try { return await Promise.race([work(), deadline]); }
  finally {
    clearTimeout(timer);
    controller.abort();
    await dispatcher?.destroy().catch(() => {});
  }
}