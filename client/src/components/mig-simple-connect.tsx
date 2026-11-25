import { useEffect, useRef, useState, type FormEvent } from "react";
import { AlertCircle, Check, ChevronDown, Compass, Loader2, Network, Save, ShieldCheck, Wrench } from "lucide-react";
import { fetchWithAuth } from "@/lib/queryClient";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import type { MigCredentialAuthorityComparison } from "../../../shared/protocol/shared/mcp-contract-types";
import type { MigSimpleConnectionTest, MigSimplePermissions, MigSimpleTool } from "@shared/mig-simple-connection";

export interface SimpleMigDiscoveryResult {
  endpoint?: string;
  identity?: string;
  capabilities?: string[] | unknown;
  capability_ids?: string[];
  handshake_status?: string;
  authority?: MigCredentialAuthorityComparison;
  assigned_trust?: string;
  assigned_risk_zone?: string;
  tools?: MigSimpleTool[];
  candidate?: { candidateId?: string };
}

export function parseRequestedIntents(value: string): string[] {
  return [...new Set(value.split(/[,\n]/).map((intent) => intent.trim()).filter(Boolean))];
}

export function isValidMigEndpoint(value: string): boolean {
  const candidate = value.trim();
  if (!/^https:\/\//i.test(candidate) || candidate.includes("#")) return false;
  try {
    const url = new URL(candidate);
    return url.protocol === "https:" && Boolean(url.hostname) && !url.username && !url.password;
  } catch {
    return false;
  }
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetchWithAuth(path, init);
  if (!response.ok) {
    const detail = (await response.text()) || response.statusText;
    throw new Error(`${response.status}: ${detail}`);
  }
  return response.json() as Promise<T>;
}

function strings(value: unknown): string[] {
  if (Array.isArray(value)) return value.map(String).filter(Boolean);
  if (typeof value === "string" && value.trim()) return [value];
  return [];
}

function AuthoritySummary({ authority }: { authority?: MigCredentialAuthorityComparison }) {
  if (!authority) return null;
  const requested = authority.requested.allowed_intents ?? [];
  const assigned = authority.assigned.allowed_intents ?? [];
  return (
    <section className="mt-4 rounded-md border bg-background/70 p-3" data-testid="simple-mig-authority">
      <h3 className="text-sm font-medium">Intent authority returned by MIG</h3>
      <div className="mt-2 grid gap-3 text-sm sm:grid-cols-2">
        <div><p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Requested</p><p className="mt-1 break-words">{requested.length ? requested.join(", ") : "None reported"}</p></div>
        <div><p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Assigned</p><p className="mt-1 break-words">{assigned.length ? assigned.join(", ") : "None assigned"}</p></div>
      </div>
      <p className="mt-2 text-xs text-muted-foreground">MIG determines assigned authority. Requested intents do not grant access by themselves.</p>
    </section>
  );
}

function ToolList({ tools, testId }: { tools?: MigSimpleTool[]; testId: string }) {
  if (!tools?.length) {
    return <p className="mt-2 text-sm text-muted-foreground">No tool metadata was returned. The server may not have advertised tools, or tool details may be unavailable.</p>;
  }
  return (
    <ul className="mt-2 divide-y rounded-md border" data-testid={testId}>
      {tools.map((tool, index) => (
        <li key={`${tool.name}-${index}`} className="flex gap-3 p-3">
          <Wrench className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
          <div className="min-w-0">
            <p className="break-words text-sm font-medium">{tool.name || "Unnamed tool"}</p>
            {tool.description
              ? <p className="mt-1 whitespace-pre-wrap break-words text-sm text-muted-foreground">{tool.description}</p>
              : <p className="mt-1 text-xs text-muted-foreground">No description provided.</p>}
            {tool.capability_id && <p className="mt-1 break-all font-mono text-xs text-muted-foreground">Capability ID: {tool.capability_id}</p>}
          </div>
        </li>
      ))}
    </ul>
  );
}

function CapabilityList({ capabilities }: { capabilities: unknown }) {
  const items = strings(capabilities);
  return (
    <div>
      <dt className="text-xs text-muted-foreground">Advertised capability IDs</dt>
      <dd className="mt-1 break-words text-sm">{items.length ? items.join(", ") : "No capabilities reported (no capability IDs)."}</dd>
    </div>
  );
}

function PermissionEditor({
  permissions,
  loading,
  loadError,
  saved,
  draftIntents,
  draftRoles,
  saving,
  dirty,
  busy,
  onRetry,
  onIntentChange,
  onRoleChange,
  onSave,
}: {
  permissions: MigSimplePermissions | null;
  loading: boolean;
  loadError: string;
  saved: MigSimplePermissions | null;
  draftIntents: string[];
  draftRoles: string[];
  saving: boolean;
  dirty: boolean;
  busy: boolean;
  onRetry: () => void;
  onIntentChange: (value: string, checked: boolean) => void;
  onRoleChange: (value: string, checked: boolean) => void;
  onSave: () => void;
}) {
  const selectableIntents = permissions
    ? [...new Set([...permissions.allowed_intents, ...permissions.intent_options])].sort()
    : [];
  return (
    <section className="mt-4 rounded-md border bg-background p-4" data-testid="simple-mig-permissions">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="font-medium">Allowed intents and roles</h3>
          <p className="mt-1 text-sm text-muted-foreground">Changes apply to this MCP principal. Requested intents are not grants; shared-principal edits are blocked by the server.</p>
        </div>
        {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" aria-label="Loading permissions" />}
      </div>
      {loading && !permissions && (
        <div className="mt-4 space-y-2" aria-label="Loading saved permissions">
          <div className="h-3 w-2/5 animate-pulse rounded bg-muted" /><div className="h-10 animate-pulse rounded bg-muted/70" /><div className="h-10 animate-pulse rounded bg-muted/70" />
        </div>
      )}
      {loadError && (
        <div className="mt-3 rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm" role="alert">
          <p>{loadError}</p><Button type="button" variant="outline" size="sm" className="mt-2" disabled={busy} onClick={onRetry}>Retry loading permissions</Button>
        </div>
      )}
      {permissions && (
        <>
          {permissions.blockers.length > 0 && (
            <div className="mt-3 rounded-md border border-amber-600/30 bg-amber-500/5 p-3 text-sm" data-testid="simple-mig-permission-blockers">
              <p className="font-medium">Permission editing is blocked</p>
              <ul className="mt-1 list-inside list-disc text-muted-foreground">{permissions.blockers.map((blocker, index) => <li key={`${blocker}-${index}`}>{blocker}</li>)}</ul>
            </div>
          )}
          {!permissions.editable && !permissions.blockers.length && <p className="mt-3 text-sm text-muted-foreground">Permissions are view-only for this registration.</p>}
          <div className="mt-4 grid gap-5 lg:grid-cols-2">
            <fieldset disabled={!permissions.editable || saving || loading} className="min-w-0 space-y-2 disabled:opacity-70">
              <legend className="text-sm font-medium">Allowed intents</legend>
              {selectableIntents.length ? selectableIntents.map((intent) => (
                <label key={intent} className="flex cursor-pointer items-start gap-2 rounded-md border p-2 text-sm">
                  <input
                    type="checkbox"
                    className="mt-0.5 accent-primary"
                    checked={draftIntents.includes(intent)}
                    onChange={(event) => {
                      if (!event.target.checked || permissions.intent_options.includes(intent)) onIntentChange(intent, event.target.checked);
                    }}
                  />
                  <span className="break-all font-mono text-xs">{intent}</span>
                  {!permissions.intent_options.includes(intent) && <span className="text-xs text-muted-foreground">current only</span>}
                </label>
              )) : <p className="text-sm text-muted-foreground">No intent options or current intents were provided.</p>}
              <p className="text-xs text-muted-foreground">Intent options define the allowed ceiling. Current out-of-ceiling intents can be removed but cannot be re-enabled.</p>
            </fieldset>
            <fieldset disabled={!permissions.editable || saving || loading} className="min-w-0 space-y-2 disabled:opacity-70">
              <legend className="text-sm font-medium">Assigned roles</legend>
              {permissions.role_options.length || permissions.assigned_roles.length ? (
                [...new Set([...permissions.role_options.map((role) => role.key), ...permissions.assigned_roles])].map((key) => {
                  const option = permissions.role_options.find((role) => role.key === key);
                  return <label key={key} className="flex cursor-pointer items-start gap-2 rounded-md border p-2 text-sm">
                    <input type="checkbox" className="mt-0.5 accent-primary" checked={draftRoles.includes(key)} onChange={(event) => onRoleChange(key, event.target.checked)} />
                    <span>{option?.label || key}{!option && <span className="ml-1 text-xs text-muted-foreground">(retained assignment)</span>}</span>
                  </label>;
                })
              ) : <p className="text-sm text-muted-foreground">No role options or assigned roles were provided.</p>}
            </fieldset>
          </div>
          <div className="mt-4 rounded-md bg-muted/40 p-3 text-xs" data-testid="simple-mig-permission-values">
            <p className="font-medium">Saved permissions returned by MIG</p>
            <p className="mt-1 break-words text-muted-foreground">Intents: {saved?.allowed_intents.length ? saved.allowed_intents.join(", ") : "None"} · Roles: {saved?.assigned_roles.length ? saved.assigned_roles.join(", ") : "None"}</p>
            {dirty && <p className="mt-2 font-medium text-amber-700 dark:text-amber-300" role="status">Draft changes are not saved.</p>}
          </div>
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <Button type="button" data-testid="simple-mig-save-permissions" disabled={!permissions.editable || !permissions.entitlement_id || !dirty || busy || Boolean(loadError)} onClick={onSave}>
              {saving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}
              {saving ? "Saving permissions…" : "Save permissions"}
            </Button>
            {!permissions.entitlement_id && <span className="text-xs text-muted-foreground">MIG did not return an entitlement ID; saving is unavailable.</span>}
          </div>
        </>
      )}
    </section>
  );
}

export function SimpleMigConnect({
  onConnected,
  existingRegistration,
  initialEndpoint = "",
}: {
  onConnected?: () => void;
  existingRegistration?: { candidateId: string; endpoint: string };
  initialEndpoint?: string;
} = {}) {
  const [endpoint, setEndpoint] = useState(initialEndpoint);
  const [intentDraft, setIntentDraft] = useState("");
  const [result, setResult] = useState<SimpleMigDiscoveryResult | null>(null);
  const [testResult, setTestResult] = useState<MigSimpleConnectionTest | null>(null);
  const [submitted, setSubmitted] = useState<{ endpoint: string; intents: string[] } | null>(null);
  const [registrationError, setRegistrationError] = useState("");
  const [testError, setTestError] = useState("");
  const [permissionError, setPermissionError] = useState("");
  const [saveError, setSaveError] = useState("");
  const [connectPending, setConnectPending] = useState(false);
  const [testPending, setTestPending] = useState(false);
  const [permissionLoading, setPermissionLoading] = useState(false);
  const [savePending, setSavePending] = useState(false);
  const [permissions, setPermissions] = useState<MigSimplePermissions | null>(null);
  const [savedPermissions, setSavedPermissions] = useState<MigSimplePermissions | null>(null);
  const [draftIntents, setDraftIntents] = useState<string[]>([]);
  const [draftRoles, setDraftRoles] = useState<string[]>([]);
  const endpointRevision = useRef(0);
  const permissionRevision = useRef(0);
  const intents = parseRequestedIntents(intentDraft);
  const validEndpoint = isValidMigEndpoint(endpoint);
  const validationMessage = endpoint.trim() && !validEndpoint ? "Enter the exact absolute HTTPS URL of the MCP connection endpoint." : "";
  const dirty = Boolean(permissions && (
    [...draftIntents].sort().join("\u0000") !== [...(savedPermissions?.allowed_intents ?? [])].sort().join("\u0000")
    || [...draftRoles].sort().join("\u0000") !== [...(savedPermissions?.assigned_roles ?? [])].sort().join("\u0000")
  ));
  const busy = connectPending || testPending || savePending || permissionLoading;

  function clearEndpointResults() {
    endpointRevision.current += 1;
    permissionRevision.current += 1;
    setConnectPending(false);
    setTestPending(false);
    setSavePending(false);
    setTestResult(null);
    setResult(null);
    setSubmitted(null);
    setRegistrationError("");
    setTestError("");
    setPermissionError("");
    setSaveError("");
    setPermissions(null);
    setSavedPermissions(null);
    setDraftIntents([]);
    setDraftRoles([]);
    setPermissionLoading(false);
  }

  function changeEndpoint(value: string) {
    if (value === endpoint) return;
    clearEndpointResults();
    setEndpoint(value);
  }

  async function loadPermissions(candidateId: string, revision: number) {
    const requestRevision = ++permissionRevision.current;
    setPermissionLoading(true);
    setPermissionError("");
    try {
      const data = await requestJson<MigSimplePermissions>(`/api/mig/admin/mcp/registrations/${encodeURIComponent(candidateId)}/permissions`);
      if (revision !== endpointRevision.current || requestRevision !== permissionRevision.current) return;
      setPermissions(data);
      setSavedPermissions(data);
      setDraftIntents(data.allowed_intents);
      setDraftRoles([...new Set(data.assigned_roles)]);
    } catch (cause) {
      if (revision !== endpointRevision.current || requestRevision !== permissionRevision.current) return;
      setPermissionError(cause instanceof Error ? cause.message : "Could not load permissions.");
    } finally {
      if (revision === endpointRevision.current && requestRevision === permissionRevision.current) setPermissionLoading(false);
    }
  }

  useEffect(() => {
    if (!existingRegistration) return;
    clearEndpointResults();
    const revision = endpointRevision.current;
    setEndpoint(existingRegistration.endpoint);
    setSubmitted({ endpoint: existingRegistration.endpoint, intents: [] });
    setResult({
      endpoint: existingRegistration.endpoint,
      candidate: { candidateId: existingRegistration.candidateId },
    });
    void loadPermissions(existingRegistration.candidateId, revision);
    // Existing registrations are selected by the containing client list. Keep
    // this initialization tied to their canonical ID, not refreshed query data.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [existingRegistration?.candidateId, existingRegistration?.endpoint]);

  async function testConnection() {
    if (!validEndpoint || busy) return;
    const target = endpoint.trim();
    const revision = endpointRevision.current;
    setTestPending(true);
    setTestError("");
    setTestResult(null);
    setRegistrationError("");
    try {
      const data = await requestJson<MigSimpleConnectionTest>("/api/mig/admin/mcp/test-connection", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ endpoint: target }),
      });
      if (revision === endpointRevision.current && target === endpoint.trim()) setTestResult(data);
    } catch (cause) {
      if (revision === endpointRevision.current && target === endpoint.trim()) setTestError(cause instanceof Error ? cause.message : "Connection test failed.");
    } finally {
      if (revision === endpointRevision.current) setTestPending(false);
    }
  }

  async function connect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!validEndpoint || !intents.length || busy || result) return;
    const target = endpoint.trim();
    const revision = endpointRevision.current;
    const submission = { endpoint: target, intents };
    permissionRevision.current += 1;
    setConnectPending(true);
    setRegistrationError("");
    setResult(null);
    setPermissions(null);
    setSavedPermissions(null);
    setSubmitted(submission);
    setPermissionError("");
    setDraftIntents([]);
    setDraftRoles([]);
    setPermissionLoading(false);
    try {
      const data = await requestJson<SimpleMigDiscoveryResult>("/api/mig/admin/mcp/connect-register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ endpoint: submission.endpoint, requested_intents: submission.intents }),
      });
      if (revision !== endpointRevision.current || target !== endpoint.trim()) return;
      setResult(data);
      onConnected?.();
      const candidateId = data.candidate?.candidateId;
      if (candidateId) void loadPermissions(candidateId, revision);
      else setPermissionError("Registration response did not include a candidate ID; permissions cannot be loaded.");
    } catch (cause) {
      if (revision === endpointRevision.current && target === endpoint.trim()) setRegistrationError(cause instanceof Error ? cause.message : "MCP registration failed. Try again.");
    } finally {
      if (revision === endpointRevision.current) setConnectPending(false);
    }
  }

  async function savePermissions() {
    if (!permissions?.editable || !permissions.entitlement_id || !dirty || busy) return;
    const candidateId = permissions.candidate_id;
    const revision = endpointRevision.current;
    const requestRevision = permissionRevision.current;
    setSavePending(true);
    setSaveError("");
    try {
      await requestJson<MigSimplePermissions>(`/api/mig/admin/mcp/registrations/${encodeURIComponent(candidateId)}/permissions`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          entitlement_id: permissions.entitlement_id,
          allowed_intents: draftIntents,
          assigned_roles: draftRoles,
        }),
      });
      if (revision !== endpointRevision.current || requestRevision !== permissionRevision.current) return;
      await loadPermissions(candidateId, revision);
    } catch (cause) {
      if (revision === endpointRevision.current && requestRevision === permissionRevision.current) setSaveError(cause instanceof Error ? cause.message : "Could not save permissions.");
    } finally {
      if (revision === endpointRevision.current) setSavePending(false);
    }
  }

  const registrationCapabilities = strings(result?.capability_ids ?? result?.capabilities);
  const registrationPrerequisitesMet = Boolean(
    testResult?.supports_lineage
    && testResult.supports_outcomes
    && testResult.secure_credential_delivery,
  );
  const unmetRegistrationPrerequisites = testResult
    ? [
      !testResult.supports_lineage && "lineage support",
      !testResult.supports_outcomes && "outcome support",
      !testResult.secure_credential_delivery && "secure credential delivery",
    ].filter(Boolean)
    : [];

  return (
    <Card className="max-w-3xl border-primary/20 shadow-sm" data-testid="simple-mig-connect">
      <CardHeader className="pb-4">
        <div className="flex items-start gap-3">
          <span className="mt-0.5 rounded-md bg-primary/10 p-2 text-primary"><Network className="h-5 w-5" /></span>
          <div>
            <CardTitle className="text-lg">{existingRegistration ? "MCP registration restrictions" : "Connect an MCP endpoint"}</CardTitle>
            <CardDescription className="mt-1 max-w-2xl">{existingRegistration
              ? "Review and edit this existing registration’s canonical intent and role permissions."
              : "Test safely, inspect what the server advertises, then register and set its allowed intents and roles."}</CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {existingRegistration ? <div className="space-y-1 rounded-md border bg-muted/20 p-3">
          <Label>Registered MCP endpoint</Label>
          <p className="break-all font-mono text-xs" data-testid="simple-mig-existing-endpoint">{existingRegistration.endpoint || "Endpoint not reported"}</p>
        </div> : <div className="space-y-2">
          <Label htmlFor="simple-mig-endpoint">MIG / MCP endpoint</Label>
          <Input id="simple-mig-endpoint" data-testid="simple-mig-endpoint" type="url" autoComplete="url" disabled={connectPending || savePending} placeholder="https://mcp.example.com/mcp" value={endpoint} onChange={(event) => changeEndpoint(event.target.value)} aria-invalid={Boolean(validationMessage)} />
          <p className="text-xs text-muted-foreground">Enter the full HTTPS connection URL, including its path. MIG will not infer a protocol, port, or path.</p>
        </div>}

        {!existingRegistration && <section className="mt-4 rounded-md border bg-muted/20 p-4" aria-labelledby="simple-mig-test-heading" data-testid="simple-mig-test">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div><h3 id="simple-mig-test-heading" className="font-medium">Test connection</h3><p className="mt-1 text-sm text-muted-foreground">Read-only check. This does not register the server or grant permissions.</p></div>
            <Button type="button" data-testid="simple-mig-test-connection" variant="outline" disabled={!validEndpoint || busy} onClick={testConnection}>
              {testPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Compass className="mr-2 h-4 w-4" />}
              {testPending ? "Testing…" : "Test connection"}
            </Button>
          </div>
          {testPending && <div className="mt-3 space-y-2" role="status"><div className="h-3 w-1/3 animate-pulse rounded bg-muted" /><div className="h-12 animate-pulse rounded bg-muted" /></div>}
          {testError && <div className="mt-3 flex gap-2 rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm" role="alert" data-testid="simple-mig-test-error"><AlertCircle className="h-4 w-4 shrink-0 text-destructive" /><p className="break-words">{testError}</p></div>}
          {testResult && (
            <div className="mt-4 border-t pt-4" data-testid="simple-mig-test-result">
              <div className="flex items-center gap-2 text-sm font-medium"><Check className="h-4 w-4 text-primary" />MCP-compatible handshake</div>
              <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
                <div className="sm:col-span-2"><dt className="text-xs text-muted-foreground">Endpoint tested</dt><dd className="mt-1 break-all font-mono text-xs">{testResult.endpoint}</dd></div>
                <div><dt className="text-xs text-muted-foreground">Identity</dt><dd className="mt-1 break-words">{testResult.identity || "Not provided by server"}</dd></div>
                <div><dt className="text-xs text-muted-foreground">Protocol version</dt><dd className="mt-1">{testResult.protocol_version || "Not provided"}</dd></div>
                <div><dt className="text-xs text-muted-foreground">Lineage support</dt><dd className="mt-1">{testResult.supports_lineage ? "Supported" : "Not supported"}</dd></div>
                <div><dt className="text-xs text-muted-foreground">Outcome support</dt><dd className="mt-1">{testResult.supports_outcomes ? "Supported" : "Not supported"}</dd></div>
              </dl>
              <div className="mt-3 rounded-md border p-3 text-sm">
                <p className="flex items-center gap-2 font-medium"><ShieldCheck className="h-4 w-4" />Secure credential delivery</p>
                <p className="mt-1 text-muted-foreground">
                  {registrationPrerequisitesMet
                    ? "Test prerequisites met: lineage, outcome, and secure credential delivery are supported. Canonical identity and policy are checked separately during registration."
                    : `Not ready for registration prerequisites: ${unmetRegistrationPrerequisites.join(", ")}${unmetRegistrationPrerequisites.length ? " not supported." : ""} Canonical identity and policy are checked separately during registration.`}
                </p>
              </div>
              <div className="mt-3">
                <CapabilityList capabilities={testResult.capabilities} />
                <h4 className="mt-4 text-sm font-medium">Tools advertised</h4>
                <ToolList tools={testResult.tools} testId="simple-mig-test-tools" />
              </div>
              <p className="mt-3 text-xs text-muted-foreground">This test is read-only: registered=false and authority_granted=false.</p>
            </div>
          )}
          {!testPending && !testError && !testResult && <p className="mt-3 text-sm text-muted-foreground">No test result yet.</p>}
        </section>}

        {existingRegistration ? <div className="mt-5 border-t pt-5">
          <p className="text-sm font-medium">Existing registration</p>
          <p className="mt-1 break-all font-mono text-xs text-muted-foreground">Candidate: {existingRegistration.candidateId}</p>
          <p className="mt-2 text-xs text-muted-foreground">This view reads and edits the canonical permission record. No registration request is made from this detail view.</p>
          <PermissionEditor
            permissions={permissions}
            loading={permissionLoading}
            loadError={permissionError}
            saved={savedPermissions}
            draftIntents={draftIntents}
            draftRoles={draftRoles}
            saving={savePending}
            dirty={dirty}
            busy={busy}
            onRetry={() => !busy && void loadPermissions(existingRegistration.candidateId, endpointRevision.current)}
            onIntentChange={(value, checked) => setDraftIntents((current) => checked && permissions?.intent_options.includes(value) ? [...new Set([...current, value])] : checked ? current : current.filter((item) => item !== value))}
            onRoleChange={(value, checked) => setDraftRoles((current) => checked ? [...new Set([...current, value])] : current.filter((item) => item !== value))}
            onSave={() => void savePermissions()}
          />
          {saveError && <div className="mt-3 rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm" role="alert" data-testid="simple-mig-save-error">{saveError}</div>}
        </div> : <form className="mt-5 space-y-4 border-t pt-5" onSubmit={connect} noValidate>
          <div className="space-y-2">
            <Label htmlFor="simple-mig-intents">Requested intents</Label>
            <Textarea id="simple-mig-intents" data-testid="simple-mig-intents" rows={3} placeholder={"inventory.read\norders.lookup"} value={intentDraft} onChange={(event) => setIntentDraft(event.target.value)} />
            <p className="text-xs text-muted-foreground">Separate intent identifiers with commas or new lines. These are registration requests, not permission grants.</p>
          </div>
          {validationMessage && <p role="status" className="text-sm text-destructive">{validationMessage}</p>}
          {intentDraft.trim() && !intents.length && <p role="status" className="text-sm text-destructive">Enter at least one intent identifier.</p>}
          <Button type="submit" data-testid="simple-mig-discover" disabled={!validEndpoint || !intents.length || busy || Boolean(result)}>
            {connectPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ChevronDown className="mr-2 h-4 w-4" />}
            {connectPending ? "Connecting and registering…" : result ? "Already registered" : "Connect and register"}
          </Button>
          {result && <p className="text-xs text-muted-foreground">This endpoint is already registered in this session. Edit its permissions below, or change the endpoint to start a new registration.</p>}
        </form>}

        {connectPending && <div className="mt-4 space-y-2 rounded-md border border-primary/20 bg-primary/5 p-3" role="status" data-testid="simple-mig-pending"><div className="h-3 w-2/5 animate-pulse rounded bg-primary/15" /><div className="h-3 w-4/5 animate-pulse rounded bg-primary/10" /><p className="text-sm text-muted-foreground">MIG is registering the endpoint and inspecting its advertised tools.</p></div>}
        {registrationError && <div className="mt-4 rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm" role="alert" data-testid="simple-mig-error"><div className="flex items-center gap-2 font-medium"><AlertCircle className="h-4 w-4" />Registration failed</div><p className="mt-1 break-words text-muted-foreground">{registrationError}</p></div>}
        {result && !existingRegistration && (
          <div className="mt-4 rounded-md border bg-muted/20 p-4" data-testid="simple-mig-result">
            <div className="flex items-center gap-2 text-sm font-medium"><Check className="h-4 w-4 text-primary" />{existingRegistration ? "Existing registration" : "Endpoint registered"}</div>
            <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
              <div><dt className="text-xs text-muted-foreground">Handshake status</dt><dd className="mt-1">{result.handshake_status || "Not provided by server"}</dd></div>
              <div><dt className="text-xs text-muted-foreground">Discovered identity</dt><dd className="mt-1 break-words">{result.identity || "Not provided by server"}</dd></div>
              <div className="sm:col-span-2"><dt className="text-xs text-muted-foreground">Registered endpoint</dt><dd className="mt-1 break-all font-mono text-xs">{result.endpoint || submitted?.endpoint || "Not provided"}</dd></div>
              <div className="sm:col-span-2"><dt className="text-xs text-muted-foreground">Submitted requested intents</dt><dd className="mt-1 break-words">{submitted?.intents.join(", ") || "None"}</dd></div>
              {(result.assigned_trust || result.assigned_risk_zone) && <div className="sm:col-span-2"><dt className="text-xs text-muted-foreground">Server-assigned trust / risk</dt><dd className="mt-1">{result.assigned_trust || "Not provided"} / {result.assigned_risk_zone || "Not provided"}</dd></div>}
            </dl>
            <div className="mt-3"><CapabilityList capabilities={registrationCapabilities} /></div>
            <AuthoritySummary authority={result.authority} />
            <div className="mt-4 border-t pt-4">
              <h3 className="text-sm font-medium">Registered tools</h3>
              <ToolList tools={result.tools} testId="simple-mig-registration-tools" />
            </div>
            {result.candidate?.candidateId && <p className="mt-3 break-all font-mono text-xs text-muted-foreground">Registration candidate: {result.candidate.candidateId}</p>}
            <PermissionEditor
              permissions={permissions}
              loading={permissionLoading}
              loadError={permissionError}
              saved={savedPermissions}
              draftIntents={draftIntents}
              draftRoles={draftRoles}
              saving={savePending}
              dirty={dirty}
              busy={busy}
              onRetry={() => !busy && result.candidate?.candidateId && void loadPermissions(result.candidate.candidateId, endpointRevision.current)}
              onIntentChange={(value, checked) => setDraftIntents((current) => checked && permissions?.intent_options.includes(value) ? [...new Set([...current, value])] : checked ? current : current.filter((item) => item !== value))}
              onRoleChange={(value, checked) => setDraftRoles((current) => checked ? [...new Set([...current, value])] : current.filter((item) => item !== value))}
              onSave={() => void savePermissions()}
            />
            {saveError && <div className="mt-3 rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm" role="alert" data-testid="simple-mig-save-error">{saveError}</div>}
          </div>
        )}
        {!connectPending && !registrationError && !result && (
          <div className="mt-4 rounded-md border border-dashed p-3 text-sm text-muted-foreground" data-testid="simple-mig-empty">
            No endpoint has been registered in this session. Use Test connection for a read-only check, or connect and register to manage permissions.
          </div>
        )}
      </CardContent>
    </Card>
  );
}
