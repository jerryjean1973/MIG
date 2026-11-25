import { afterEach, describe, expect, it, vi } from "vitest";
import express from "express";
import { createServer, type Server } from "node:http";
import { randomUUID } from "node:crypto";
import {
  MIG_OWNER_BRIDGE_SCHEMA, encodeMigOwnerValue, decodeMigOwnerValue,
  assertMigOwnerRequest, assertMigOwnerOperationScope, signMigOwnerMessage,
  verifyMigOwnerMessage,
} from "../shared/contracts/mig-owner-bridge-v1";
import { registerMigOwnerBridge } from "../server/mig/mig-owner-bridge";
import { ownerCall } from "../server/standalone/owner-client";

// Public fixtures only; these are not production credentials or identities.
const signingKey = "public-test-fixture-signing-value-never-use-in-production";
const tenant = "fixture-tenant";
const servers: Server[] = [];
afterEach(async () => {
  vi.unstubAllEnvs();
  for (const server of servers.splice(0)) {
    server.closeAllConnections();
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
});
async function listen(app: express.Express) {
  const server = createServer(app);
  servers.push(server);
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw Error("FIXTURE_LISTEN_FAILED");
  return `http://127.0.0.1:${address.port}/api/mig/owner-bridge/v1`;
}
function request(operation: any = "catalog.read", args: unknown[] = []) {
  return { schema_version: MIG_OWNER_BRIDGE_SCHEMA, operation, tenant_id: tenant,
    nonce: randomUUID(), expires_at: Date.now() + 60_000, args: encodeMigOwnerValue(args) as unknown[] };
}
function configureClient(url: string) {
  vi.stubEnv("NODE_ENV", "test");
  vi.stubEnv("MIG_TENANT_ID", tenant);
  vi.stubEnv("MIG_OWNER_BRIDGE_SECRET", signingKey);
  vi.stubEnv("MIG_OWNER_BRIDGE_URL", url);
}
describe("lossless owner wire", () => {
  it("preserves undefined, Date, Set, Map and reserved-tag evidence", () => {
    const source = { absent: undefined, date: new Date("2026-01-01T00:00:00.000Z"),
      set: new Set(["a", "b"]), map: new Map([["a", 1]]),
      ordinary: { $mig_wire_type: "Date", value: "a literal source assertion" } };
    expect(decodeMigOwnerValue(JSON.parse(JSON.stringify(encodeMigOwnerValue(source))))).toEqual(source);
  });
  it("rejects values JSON would silently change", () => {
    for (const value of [NaN, Infinity, 1n, () => {}, /unsupported-native-object/]) {
      expect(() => encodeMigOwnerValue(value)).toThrow();
    }
    expect(() => decodeMigOwnerValue(JSON.parse('{"__proto__":{"admin":true}}'))).toThrow("MIG_OWNER_UNSAFE_OBJECT");
    expect(() => decodeMigOwnerValue({ $mig_wire_type: "Date", value: "not-a-date" })).toThrow("MIG_OWNER_INVALID_DATE");
  });
  it("binds signature to exact content independent of object key order", () => {
    const signature = signMigOwnerMessage({ b: 2, a: 1 }, signingKey);
    expect(verifyMigOwnerMessage({ a: 1, b: 2 }, signature, signingKey)).toBe(true);
    expect(verifyMigOwnerMessage({ a: 1, b: 3 }, signature, signingKey)).toBe(false);
  });
  it("separates literal source fields from authenticated execution scope", () => {
    expect(() => assertMigOwnerOperationScope("tool.execute",
      ["fixture", { source_json: { tenant_id: "source-system-id" } }, { tenantId: tenant }], tenant)).not.toThrow();
    expect(() => assertMigOwnerOperationScope("tool.execute",
      ["fixture", {}, { tenantId: "other-tenant" }], tenant)).toThrow("MIG_OWNER_TENANT_MISMATCH");
    expect(() => assertMigOwnerOperationScope("knowledge.bindMcpCapability",
      [{ tenant_id: "other-tenant" }], tenant)).toThrow("MIG_OWNER_TENANT_MISMATCH");
  });
  it("rejects expired, unregistered and extra-field requests", () => {
    expect(() => assertMigOwnerRequest({ ...request(), expires_at: 1 })).toThrow();
    expect(() => assertMigOwnerRequest(request("unregistered.operation"))).toThrow();
    expect(() => assertMigOwnerRequest({ ...request(), admin: true })).toThrow();
  });
});
describe("authenticated owner transport", () => {
  it("dispatches once with durable replay protection", async () => {
    const app = express(); app.use(express.json());
    const seen = new Set<string>();
    const dispatch = vi.fn(async () => ({ date: new Date("2026-01-01T00:00:00.000Z") }));
    registerMigOwnerBridge(app, {
      secret: signingKey, allowedTenantIds: new Set([tenant]),
      claimNonce: async (scope, nonce) => {
        const key = scope + ":" + nonce; if (seen.has(key)) return false; seen.add(key); return true;
      }, dispatch,
    });
    const url = await listen(app), body = request();
    const options = { method: "POST", headers: { "content-type": "application/json",
      "x-mig-owner-signature": signMigOwnerMessage(body, signingKey) }, body: JSON.stringify(body) };
    expect((await fetch(url, options)).status).toBe(200);
    expect((await fetch(url, options)).status).toBe(409);
    expect(dispatch).toHaveBeenCalledTimes(1);
  });
  it("rejects unsigned requests and unconfigured tenants before dispatch", async () => {
    const app = express(); app.use(express.json());
    const dispatch = vi.fn(async () => null);
    registerMigOwnerBridge(app, { secret: signingKey, allowedTenantIds: new Set([tenant]),
      claimNonce: async () => true, dispatch });
    const url = await listen(app);
    const body = request();
    expect((await fetch(url, { method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify(body) })).status).toBe(401);
    const other = { ...body, tenant_id: "unconfigured-tenant" };
    expect((await fetch(url, { method: "POST", headers: { "content-type": "application/json",
      "x-mig-owner-signature": signMigOwnerMessage(other, signingKey) }, body: JSON.stringify(other) })).status).toBe(401);
    expect(dispatch).not.toHaveBeenCalled();
  });
  it("verifies signed owner response and restores native wire types", async () => {
    const app = express(); app.use(express.json());
    registerMigOwnerBridge(app, { secret: signingKey, allowedTenantIds: new Set([tenant]),
      claimNonce: async () => true, dispatch: async () => ({ result: new Set(["fixture-only"]) }) });
    configureClient(await listen(app));
    expect(await ownerCall("catalog.read", [])).toEqual({ result: new Set(["fixture-only"]) });
  });
  it("never retries an uncertain upstream operation", async () => {
    const app = express(); let count = 0;
    app.post("/api/mig/owner-bridge/v1", (_req, res) => { count++; res.sendStatus(503); });
    configureClient(await listen(app));
    await expect(ownerCall("catalog.read", [])).rejects.toThrow("MIG_OWNER_HTTP_503");
    expect(count).toBe(1);
  });
  it("rejects a substituted successful response", async () => {
    const app = express();
    app.post("/api/mig/owner-bridge/v1", (_req, res) => res.json({ value: "not bound to the request" }));
    configureClient(await listen(app));
    await expect(ownerCall("catalog.read", [])).rejects.toThrow("MIG_OWNER_RESPONSE_BINDING_INVALID");
  });
  it("rejects non-HTTPS owner endpoints outside test mode", async () => {
    configureClient("http://127.0.0.1:1/api/mig/owner-bridge/v1");
    vi.stubEnv("NODE_ENV", "production");
    await expect(ownerCall("catalog.read", [])).rejects.toThrow("MIG_OWNER_ENDPOINT_INVALID");
  });
});
