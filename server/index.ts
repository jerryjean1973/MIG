import express from "express";
import { createServer, type Server } from "node:http";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { pool, requireMigPool, db } from "./db";
import { registerMigAuthentication, oidcConfigured } from "./standalone/auth";
import { ownerConfigured } from "./standalone/owner-client";
import { refreshOwnerCatalog } from "./standalone/catalog";
import { configureStructuralHistoryDb } from "../shared/persistence/structural-history-store";
import { registerMcpBodyParser } from "./mcp/mcp-body-parser";

export async function createMigApplication() {
  const app = express();
  app.disable("x-powered-by");
  app.use((_req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    next();
  });
  registerMcpBodyParser(app);
  app.use(express.json({ limit: "8mb", strict: true }));
  configureStructuralHistoryDb(pool ? db as any : null);
  let controlPlaneReady = false;
  let ownerAvailable = false;
  let refreshing = false;
  let controlPlane = express.Router();

  registerMigAuthentication(app);
  app.get("/api/health", async (_req, res) => {
    res.setHeader("Cache-Control", "no-store");
    const configured = {
      database: !!pool && !!process.env.MIG_TENANT_ID,
      oidc: oidcConfigured(), downstream: ownerConfigured(),
    };
    res.json({
      status: !configured.database || !configured.oidc || !configured.downstream
        ? "configuration_required" : controlPlaneReady && ownerAvailable ? "ready" : "degraded",
      configured, control_plane_ready: controlPlaneReady,
    });
  });
  app.use((req, res, next) => controlPlane(req, res, next));
  app.use("/api", (_req, res) => {
    res.status(controlPlaneReady ? 404 : 503).json({
      error: controlPlaneReady ? "MIG_ROUTE_NOT_FOUND" : "MIG_CONTROL_PLANE_UNAVAILABLE",
    });
  });
  let vite: { close(): Promise<void> } | undefined;
  if (process.env.NODE_ENV === "production" || process.env.NODE_ENV === "test") {
    app.use(express.static(resolve("dist/public"), { index: false, maxAge: "1h" }));
    app.get(["/", "/mig"], (_req, res) => res.sendFile(resolve("dist/public/index.html")));
  } else {
    const { createServer } = await import("vite");
    const development = await createServer({
      configFile: resolve("vite.config.ts"),
      server: { middlewareMode: true, allowedHosts: true },
    });
    vite = development;
    app.use(development.middlewares);
  }
  app.use((error: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    res.status(error?.status === 413 ? 413 : 500).json({
      error: error?.status === 413 ? "MIG_REQUEST_TOO_LARGE" : "MIG_REQUEST_FAILED",
    });
  });
  async function refresh() {
    if (refreshing || !pool || !process.env.MIG_TENANT_ID || !ownerConfigured()) return;
    refreshing = true;
    try {
      await refreshOwnerCatalog();
      ownerAvailable = true;
      if (!controlPlaneReady) {
        const schema = await requireMigPool().query(
          "SELECT to_regclass('mig_principals') AS principals, to_regclass('mig_standalone_sessions') AS sessions, to_regclass('mcp_tool_invocations') AS invocations",
        );
        if (!schema.rows[0]?.principals || !schema.rows[0]?.sessions || !schema.rows[0]?.invocations) {
          throw new Error("MIG_MIGRATIONS_REQUIRED");
        }
        const candidate = express.Router();
        const { registerMigRoutes } = await import("./routes/mig-routes");
        registerMigRoutes(candidate as unknown as express.Express);
        const { registerMcpRoutes } = await import("./routes/mcp-routes");
        registerMcpRoutes(candidate as unknown as express.Express);
        controlPlane = candidate;
        controlPlaneReady = true;
      }
    } catch {
      ownerAvailable = false;
      console.error("MIG_CONTROL_PLANE_INITIALIZATION_UNAVAILABLE");
    } finally { refreshing = false; }
  }
  // Public configuration screen starts even when an external owner is offline.
  void refresh();
  const timer = setInterval(() => void refresh(), 60_000);
  timer.unref();
  return { app, refresh, close: async () => { clearInterval(timer); await vite?.close(); await pool?.end(); } };
}

export async function startMigApplication(): Promise<Server> {
  const application = await createMigApplication();
  const server = createServer(application.app);
  const port = Number(process.env.PORT ?? 5000);
  await new Promise<void>((resolveReady, reject) => {
    server.once("error", reject);
    server.listen(port, "0.0.0.0", resolveReady);
  });
  console.log(`MIG listening on port ${port}`);
  async function shutdown() {
    server.close();
    await application.close();
  }
  process.once("SIGTERM", () => void shutdown());
  process.once("SIGINT", () => void shutdown());
  return server;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await startMigApplication();
}
