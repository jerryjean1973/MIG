import type { Express, Response } from "express";
import { testMigConnection, readSimpleMigPermissions, saveSimpleMigPermissions } from "../mig/mig-simple-connection";

/** Registered after MIG's existing enterprise administrator guard. */
export function registerMigSimpleConnectionRoutes(app: Express) {
  function auth(res: Response) {
    res.setHeader("Cache-Control", "no-store");
    const context = res.locals.enterpriseAdminContext;
    if (!context) res.status(401).json({ error: "Authentication required" });
    return context;
  }
  function failure(res: Response, error: unknown) {
    const message = error instanceof Error ? error.message : "";
    const safe = /^MIG_[A-Z0-9_]+$/.test(message) ? message : "MIG_CONNECTION_TEMPORARILY_UNAVAILABLE";
    const status = safe.endsWith("NOT_FOUND") ? 404 : safe.includes("CONFLICT") ? 409 :
      safe.includes("NOT_EDITABLE") || safe.includes("OUTSIDE_CEILING") ? 403 :
      safe.endsWith("TEMPORARILY_UNAVAILABLE") ? 503 : 400;
    res.status(status).json({ error: safe });
  }
  app.post("/api/mig/admin/mcp/test-connection", async (req, res) => {
    if (!auth(res)) return;
    try { res.json(await testMigConnection(req.body?.endpoint)); }
    catch (error) { failure(res, error); }
  });
  const path = "/api/mig/admin/mcp/registrations/:candidateId/permissions";
  app.get(path, async (req, res) => {
    const context = auth(res); if (!context) return;
    try { res.json(await readSimpleMigPermissions(context.tenantId, req.params.candidateId)); }
    catch (error) { failure(res, error); }
  });
  app.put(path, async (req, res) => {
    const context = auth(res); if (!context) return;
    try { res.json(await saveSimpleMigPermissions(context.tenantId, context.actorUserId, req.params.candidateId, req.body)); }
    catch (error) { failure(res, error); }
  });
}
