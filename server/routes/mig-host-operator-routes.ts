import type { Express, Request, Response } from "express";
import { verifyInternalSession } from "../routes-shared";
import { storage } from "../storage";
import { authenticateMigClient } from "../mig/mig-client-lineage";
import { requireEnterpriseSchemaReady } from "../migrations/enterprise-schema-readiness";
import {
  hostOperatorChallenge, requestHostOperator, hostOperatorView,
  listHostOperatorRequests, readHostOperatorRequest, decideHostOperatorRequest,
} from "../mig/mig-host-operator-registration";

/** No unauthenticated identity bootstrap and no caller-supplied tenant or role. */
async function requester(req: Request, res: Response) {
  res.setHeader("Cache-Control", "no-store");
  try {
    const session = await verifyInternalSession(req);
    if (session) return { tenantId: session.orgId, actorId: session.userId };
    const apiKey = req.header("x-mig-api-key");
    const client = apiKey ? await authenticateMigClient(apiKey) : undefined;
    const principal = client ? await storage.getMigPrincipal(client.tenantId, client.principalId) : undefined;
    const binding = client ? await storage.getActiveMigCredentialBinding(`mig-key:${client.credentialHash}`) : undefined;
    if (!client || principal?.status !== "active" || !binding || binding.expiresAt && binding.expiresAt <= new Date()) {
      res.status(401).json({ error: "MIG_HOST_OPERATOR_AUTHENTICATION_REQUIRED" });
      return;
    }
    return { tenantId: client.tenantId, actorId: client.principalId };
  } catch (error) {
    failure(res, error);
  }
}
function failure(res: Response, error: unknown) {
  if ((error as { code?: string })?.code === "23505") {
    return void res.status(409).json({ error: "MIG_HOST_OPERATOR_IDENTITY_ALREADY_EXISTS" });
  }
  const message = error instanceof Error ? error.message : "";
  if (!/^MIG_[A-Z0-9_:,]+$/.test(message)) {
    console.warn("[MIG host operator] request failed before completion");
    return void res.status(503).json({ error: "MIG_HOST_OPERATOR_TEMPORARILY_UNAVAILABLE" });
  }
  const status = message.includes("NOT_FOUND") ? 404
    : message.includes("INDEPENDENT_ADMIN") || message.includes("HUMAN_ADMIN") ? 403
    : message.includes("ALREADY") || message.includes("NOT_READY") || message.includes("CONFLICT") || message.includes("BUSY") ? 409 : 400;
  res.status(status).json({ error: message });
}

export function registerMigHostOperatorRoutes(app: Express) {
  const root = "/api/mig/host-operator-requests";
  app.use(root, requireEnterpriseSchemaReady);
  app.get(`${root}/contract`, async (req, res) => {
    if (!await requester(req, res)) return;
    res.json({
      contract: "mig.host-operator.enrollment.v1",
      automation: { challenge: `POST ${root}/challenge`, request: `POST ${root}`,
        status: `GET ${root}/:requestId`, administrator_decision: "POST /api/mig/admin/host-operator-requests/:requestId/decision" },
      authentication: "Existing authenticated session or active full MIG client credential; approval requires an independent human administrator session.",
      signing: "Sign the exact challenge signing_payload UTF-8 bytes with Ed25519; submit the base64 signature, normalized spec and expires_at. Never send a private key.",
      template: { principal_id: "smartdev-host-operator-dev", client_id: "smartdev-bc-dev",
        display_name: "SmartDev Host Operator", project: "BC", environment: "DEV",
        capability_ids: ["codex.version"], intent_id: "<existing approved intent id>",
        domain_id: "<existing governed domain id>", public_key_pem: "<Ed25519 SPKI public key PEM>" },
      invariants: ["Discovery is not execution permission", "One initial capability; no wildcard grants",
        "Exact project/environment resource scope", "Independent administrator; no self-approval",
        "Existing tenant policy, intent and capability contracts must permit activation",
        "Public-key possession does not prove SmartDev enrollment, deployment, execution or resumption"],
      administrator_decision: { decision: "approve",
        validation_evidence: { identity_auth: "<reviewed evidence reference>", current_intent: "<reviewed evidence reference>",
          governed_invocation: "<reviewed evidence reference>", mig_root_lineage: "<reviewed evidence reference>" } },
    });
  });
  app.post(`${root}/challenge`, async (req, res) => {
    const auth = await requester(req, res); if (!auth) return;
    try { res.json(hostOperatorChallenge(auth.tenantId, auth.actorId, req.body)); }
    catch (error) { failure(res, error); }
  });
  app.post(root, async (req, res) => {
    const auth = await requester(req, res); if (!auth) return;
    try {
      const result = await requestHostOperator(auth.tenantId, auth.actorId, req.body);
      res.status(result.idempotent ? 200 : 202).json(await hostOperatorView(result.candidate));
    } catch (error) { failure(res, error); }
  });
  app.get(`${root}/:requestId`, async (req, res) => {
    const auth = await requester(req, res); if (!auth) return;
    try {
      res.json(await readHostOperatorRequest(auth.tenantId, auth.actorId, req.params.requestId));
    } catch (error) { failure(res, error); }
  });
  // These routes are registered behind the existing /api/mig/admin guard.
  const adminRoot = "/api/mig/admin/host-operator-requests";
  app.get(adminRoot, async (_req, res) => {
    const auth = res.locals.enterpriseAdminContext;
    res.setHeader("Cache-Control", "no-store");
    if (!auth) return void res.status(401).json({ error: "Authentication required" });
    try { res.json(await listHostOperatorRequests(auth.tenantId)); }
    catch (error) { failure(res, error); }
  });
  app.post(`${adminRoot}/:requestId/decision`, async (req, res) => {
    const auth = res.locals.enterpriseAdminContext;
    res.setHeader("Cache-Control", "no-store");
    if (!auth) return void res.status(401).json({ error: "Authentication required" });
    try { res.json(await decideHostOperatorRequest(auth.tenantId, auth.actorUserId, req.params.requestId, req.body)); }
    catch (error) { failure(res, error); }
  });
}
