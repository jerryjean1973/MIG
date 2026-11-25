import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Globe2, Loader2, Network, RefreshCw, Search, Shield, Users } from "lucide-react";
import { fetchWithAuth } from "@/lib/queryClient";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { SimpleMigConnect } from "@/components/mig-simple-connect";
import { MigDnsDiscovery } from "@/components/mig-dns-discovery";

type Client = {
  component_id: string;
  identity?: string;
  display_name?: string;
  client_class?: string;
  status?: string;
  endpoint?: string;
  lifecycle_status?: string;
  max_risk_zone?: string;
  credential?: { masked?: string; class?: string; assigned_authority?: { allowed_intents?: string[] } };
};
type Agent = {
  agentId: string;
  displayName?: string;
  status?: string;
  allowedIntents?: string[];
  allowedRiskZones?: string[];
  maxCapabilityClassification?: string;
  requiresHumanApproval?: boolean;
  credentialAuthority?: { allowedIntents?: string[]; maxRiskZone?: string; maxCapabilityClassification?: string };
  [key: string]: unknown;
};
type Candidate = {
  candidate_id?: string;
  component_id?: string;
  endpoint?: string;
  identity?: string;
  principal_id?: string;
  status?: string;
  lifecycle_status?: string;
};
type ScanResult = {
  candidates?: Candidate[];
  candidate?: Candidate;
  rejected_scopes?: unknown[];
  scope_rejections?: unknown[];
  failures?: unknown[];
  failure_details?: unknown[];
};

async function getJson<T>(url: string): Promise<T> {
  const response = await fetchWithAuth(url);
  if (!response.ok) throw new Error(`${response.status}: ${(await response.text()) || response.statusText}`);
  return response.json() as Promise<T>;
}
async function sendJson<T>(url: string, method: string, body: unknown): Promise<T> {
  const response = await fetchWithAuth(url, {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(`${response.status}: ${(await response.text()) || response.statusText}`);
  return response.json() as Promise<T>;
}

function LoadingRows() {
  return <div className="space-y-2 p-4" aria-label="Loading clients">
    {[0, 1, 2].map((row) => <div key={row} className="h-14 animate-pulse rounded-md bg-muted/70" />)}
  </div>;
}

function isExplicitScanTarget(value: string, portValue: string): boolean {
  const targetValue = value.trim();
  if (!targetValue) return false;
  if (/^https?:\/\//i.test(targetValue)) {
    try {
      const parsed = new URL(targetValue);
      return Boolean(parsed.hostname) && !parsed.username && !parsed.password;
    } catch {
      return false;
    }
  }
  const numericPort = Number(portValue);
  const isHostOrIp = /^[a-zA-Z0-9.-]+$/.test(targetValue) || /^\[[0-9a-fA-F:]+\]$/.test(targetValue);
  return isHostOrIp && Number.isInteger(numericPort) && numericPort >= 1 && numericPort <= 65535;
}

function normalizeCandidate(value: unknown): Candidate {
  if (!value || typeof value !== "object") return {};
  const raw = value as Record<string, unknown>;
  const target = raw.target && typeof raw.target === "object" ? raw.target as Record<string, unknown> : {};
  const candidateId = raw.candidate_id ?? raw.candidateId ?? raw.id;
  const componentId = raw.component_id ?? raw.componentId;
  const principalId = raw.principal_id ?? raw.principalId;
  const endpoint = raw.endpoint ?? target.url;
  const state = raw.status ?? raw.state;
  return {
    ...(typeof candidateId === "string" ? { candidate_id: candidateId } : {}),
    ...(typeof componentId === "string" ? { component_id: componentId } : {}),
    ...(typeof endpoint === "string" ? { endpoint } : {}),
    ...(typeof raw.identity === "string" ? { identity: raw.identity } : {}),
    ...(typeof principalId === "string" ? { principal_id: principalId } : {}),
    ...(typeof state === "string" ? { status: state } : {}),
  };
}

function normalizeScanResult(value: unknown): ScanResult {
  if (!value || typeof value !== "object") return {};
  const raw = value as Record<string, unknown>;
  const candidates = Array.isArray(raw.candidates) ? raw.candidates.map(normalizeCandidate) : undefined;
  const candidate = raw.candidate ? normalizeCandidate(raw.candidate) : undefined;
  return {
    candidates,
    candidate,
    rejected_scopes: Array.isArray(raw.rejected_scopes) ? raw.rejected_scopes : undefined,
    scope_rejections: Array.isArray(raw.scope_rejections) ? raw.scope_rejections : undefined,
    failures: Array.isArray(raw.failures) ? raw.failures : undefined,
    failure_details: Array.isArray(raw.failure_details) ? raw.failure_details : undefined,
  };
}

export function MigSimpleWorkspace() {
  const queryClient = useQueryClient();
  const [selected, setSelected] = useState<{ kind: "client"; client: Client } | { kind: "agent"; agent: Agent } | null>(null);
  const [discoverOpen, setDiscoverOpen] = useState(false);
  const [discoveryMode, setDiscoveryMode] = useState<"dns" | "network" | null>(null);
  const [target, setTarget] = useState("");
  const [port, setPort] = useState("");
  const [scope, setScope] = useState("");
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);

  const clientsQuery = useQuery({ queryKey: ["/api/mig/admin/clients"], queryFn: () => getJson<Client[]>("/api/mig/admin/clients") });
  const agentsQuery = useQuery({ queryKey: ["/api/mig/admin/agents"], queryFn: () => getJson<Agent[]>("/api/mig/admin/agents") });
  const candidatesQuery = useQuery({ queryKey: ["/api/mig/admin/onboarding/candidates"], queryFn: () => getJson<Candidate[]>("/api/mig/admin/onboarding/candidates") });
  const registrationsQuery = useQuery({ queryKey: ["/api/mig/admin/mcp/registrations"], queryFn: () => getJson<Candidate[]>("/api/mig/admin/mcp/registrations") });

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/clients"] });
    void queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/agents"] });
    void queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/onboarding/candidates"] });
    void queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/mcp/registrations"] });
  };
  const candidateByComponent = useMemo(() => {
    const groups = new Map<string, Map<string, Candidate>>();
    for (const row of [...(candidatesQuery.data ?? []), ...(registrationsQuery.data ?? [])]) {
      if (!row.component_id || !row.candidate_id) continue;
      const group = groups.get(row.component_id) ?? new Map<string, Candidate>();
      group.set(row.candidate_id, { ...group.get(row.candidate_id), ...row });
      groups.set(row.component_id, group);
    }
    const map = new Map<string, Candidate>();
    for (const [componentId, group] of groups) {
      const rows = [...group.values()];
      const active = rows.filter(row => ["registered", "trusted"].includes(row.lifecycle_status ?? row.status ?? ""));
      const matches = active.length ? active : rows;
      // Historical registrations can share a component ID. An ambiguous link
      // must not select an arbitrary permission record.
      if (matches.length === 1) map.set(componentId, matches[0]);
    }
    return map;
  }, [candidatesQuery.data, registrationsQuery.data]);
  const agentById = useMemo(() => new Map((agentsQuery.data ?? []).map((agent) => [agent.agentId, agent])), [agentsQuery.data]);
  const legacyAgents = useMemo(() => {
    const clientIds = new Set((clientsQuery.data ?? []).map((client) => client.component_id));
    return (agentsQuery.data ?? []).filter((agent) => !clientIds.has(agent.agentId));
  }, [agentsQuery.data, clientsQuery.data]);

  const scopeMutation = useMutation({
    mutationFn: ({ agentId, body }: { agentId: string; body: Record<string, unknown> }) => sendJson<Agent>(`/api/mig/admin/agents/${encodeURIComponent(agentId)}`, "PATCH", body),
    onSuccess: (updated, variables) => {
      setSelected((current) => current?.kind === "agent" && current.agent.agentId === variables.agentId ? { ...current, agent: updated } : current);
      refresh();
    },
  });
  const statusMutation = useMutation({
    mutationFn: ({ agentId, status }: { agentId: string; status: string }) => sendJson<Agent>(`/api/mig/admin/agents/${encodeURIComponent(agentId)}/status`, "POST", { status }),
    onSuccess: (updated, variables) => {
      setSelected((current) => current?.kind === "agent" && current.agent.agentId === variables.agentId ? { ...current, agent: updated } : current);
      refresh();
    },
  });
  const scanMutation = useMutation({
    mutationFn: () => sendJson<unknown>("/api/mig/admin/onboarding/scan-network", "POST", {
      target: target.trim(),
      ...(port.trim() ? { port: Number(port) } : {}),
      approved_scopes: scope.split(/[\n,]/).map((item) => item.trim()).filter(Boolean),
    }),
    onSuccess: (result) => { setScanResult(normalizeScanResult(result)); refresh(); },
  });

  const loadError = clientsQuery.error || agentsQuery.error;
  const associationError = candidatesQuery.error || registrationsQuery.error;
  const isLoading = clientsQuery.isLoading || agentsQuery.isLoading || candidatesQuery.isLoading || registrationsQuery.isLoading;
  const selectedRegistration = selected?.kind === "client" ? candidateByComponent.get(selected.client.component_id) : undefined;
  const validScanTarget = isExplicitScanTarget(target, port);
  const selectClient = (client: Client) => {
    scopeMutation.reset();
    statusMutation.reset();
    const exactAgent = agentById.get(client.component_id);
    if (client.client_class?.toUpperCase() === "AGENT" && exactAgent) {
      setSelected({ kind: "agent", agent: exactAgent });
      return;
    }
    setSelected({ kind: "client", client });
  };
  const selectAgent = (agent: Agent) => {
    scopeMutation.reset();
    statusMutation.reset();
    setSelected({ kind: "agent", agent });
  };
  const returnToList = () => {
    scopeMutation.reset();
    statusMutation.reset();
    setSelected(null);
  };

  if (selected) {
    const title = selected.kind === "client"
      ? selected.client.display_name || selected.client.identity || selected.client.component_id
      : selected.agent.displayName || selected.agent.agentId;
    return <div className="space-y-4" data-testid="mig-simple-client-detail">
      <Button variant="ghost" size="sm" onClick={returnToList}><ArrowLeft className="mr-2 h-4 w-4" />All clients</Button>
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="break-words text-base">{title}</CardTitle>
          <CardDescription className="break-all font-mono text-xs">
            {selected.kind === "client" ? selected.client.component_id : selected.agent.agentId}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {selected.kind === "client" ? <>
            <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
              <div><dt className="text-xs text-muted-foreground">Class / status</dt><dd className="mt-1">{selected.client.client_class || "Legacy client"} / {selected.client.status || selected.client.lifecycle_status || "Unknown"}</dd></div>
              <div><dt className="text-xs text-muted-foreground">Endpoint</dt><dd className="mt-1 break-all font-mono text-xs">{selected.client.endpoint || selectedRegistration?.endpoint || "Not reported"}</dd></div>
              <div><dt className="text-xs text-muted-foreground">Principal</dt><dd className="mt-1 break-all font-mono text-xs">{selectedRegistration?.principal_id || "Not reported"}</dd></div>
              <div><dt className="text-xs text-muted-foreground">Credential ceiling</dt><dd className="mt-1">{selected.client.credential?.assigned_authority?.allowed_intents?.join(", ") || "Not reported"}</dd></div>
            </dl>
            {selected.client.client_class?.toUpperCase() === "AGENT" ? <p className="mt-4 rounded-md border border-dashed p-3 text-sm text-muted-foreground">
              {agentById.has(selected.client.component_id)
                ? "This registered agent is managed through its exact legacy agent identity."
                : "Agent restrictions are unavailable: the tenant agent list did not return an exact agentId match. No MCP permission record is inferred."}
            </p> : selectedRegistration?.candidate_id ? (
              <div className="mt-5 border-t pt-4">
                <p className="mb-3 text-sm font-medium">Canonical registration restrictions</p>
                <SimpleMigConnect
                  onConnected={refresh}
                  existingRegistration={{ candidateId: selectedRegistration.candidate_id, endpoint: selectedRegistration.endpoint || selected.client.endpoint || "" }}
                />
              </div>
            ) : associationError ? <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm" role="alert">
              <span>Registration links could not be loaded. No identity match is inferred.</span>
              <Button size="sm" variant="outline" onClick={refresh}><RefreshCw className="mr-2 h-4 w-4" />Retry links</Button>
            </div> : <p className="mt-4 rounded-md border border-dashed p-3 text-sm text-muted-foreground">
              No unique exact component identity match to an MCP registration was returned. This client remains visible; no registration or restriction is inferred.
            </p>}
          </> : <LegacyAgentEditor
            key={selected.agent.agentId}
            agent={selected.agent}
            onSave={(body) => scopeMutation.mutate({ agentId: selected.agent.agentId, body })}
            onStatus={(status) => statusMutation.mutate({ agentId: selected.agent.agentId, status })}
            saving={scopeMutation.isPending && scopeMutation.variables?.agentId === selected.agent.agentId}
            statusPending={statusMutation.isPending && statusMutation.variables?.agentId === selected.agent.agentId}
            error={(scopeMutation.variables?.agentId === selected.agent.agentId ? scopeMutation.error : null)
              || (statusMutation.variables?.agentId === selected.agent.agentId ? statusMutation.error : null)}
            scopeSaved={scopeMutation.isSuccess && scopeMutation.variables?.agentId === selected.agent.agentId}
            statusSaved={statusMutation.isSuccess && statusMutation.variables?.agentId === selected.agent.agentId}
          />}
        </CardContent>
      </Card>
    </div>;
  }

  return <div className="space-y-4" data-testid="mig-simple-workspace">
    <div className="flex flex-wrap items-end justify-between gap-3">
      <div>
        <h2 className="text-lg font-semibold">Clients</h2>
        <p className="mt-1 text-sm text-muted-foreground">All clients visible to this tenant, including legacy agents. Select a client to review its current restrictions.</p>
      </div>
      <Button onClick={() => { setDiscoverOpen((open) => !open); setDiscoveryMode(null); setScanResult(null); }}>
        <Search className="mr-2 h-4 w-4" />{discoverOpen ? "Close discovery" : "Discover"}
      </Button>
    </div>

    <div className="grid gap-3 sm:grid-cols-3">
      <CountBox label="Registered clients" value={clientsQuery.data?.length} loading={clientsQuery.isLoading} error={clientsQuery.isError} />
      <CountBox label="Legacy agents" value={legacyAgents.length} loading={agentsQuery.isLoading || clientsQuery.isLoading} error={agentsQuery.isError || clientsQuery.isError} />
      <CountBox label="Onboarding candidates" value={candidatesQuery.data?.length} loading={candidatesQuery.isLoading} error={candidatesQuery.isError} />
    </div>

    {discoverOpen && <Card className="border-primary/30" data-testid="mig-simple-discover">
      <CardHeader className="pb-3">
        <CardTitle className="text-base">Choose a discovery path</CardTitle>
        <CardDescription>Discovery reports candidates. It does not register clients or grant restrictions.</CardDescription>
      </CardHeader>
      <CardContent>
        {!discoveryMode ? <div className="grid gap-3 md:grid-cols-2">
          <button type="button" className="rounded-md border p-4 text-left transition-colors hover:bg-muted/40" onClick={() => setDiscoveryMode("dns")}>
            <Globe2 className="mb-2 h-5 w-5 text-primary" /><span className="block text-sm font-medium">DNS-based discovery</span>
            <span className="mt-1 block text-xs text-muted-foreground">Discover advertised MCP services in your organization’s domain, or specify an alternate private DNS zone.</span>
          </button>
          <button type="button" className="rounded-md border p-4 text-left transition-colors hover:bg-muted/40" onClick={() => setDiscoveryMode("network")}>
            <Network className="mb-2 h-5 w-5 text-primary" /><span className="block text-sm font-medium">Network-based discovery</span>
            <span className="mt-1 block text-xs text-muted-foreground">Scan one explicit URL or host and port, limited to tenant-configured approved scopes.</span>
          </button>
        </div> : <>
          <Button size="sm" variant="ghost" className="mb-3 px-2" onClick={() => { setDiscoveryMode(null); setScanResult(null); }}><ArrowLeft className="mr-1 h-4 w-4" />Change method</Button>
          {discoveryMode === "dns" ? <MigDnsDiscovery onConnected={refresh} /> : <div className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="space-y-1 sm:col-span-2"><Label htmlFor="mig-network-target">Exact URL or host/IP</Label><Input id="mig-network-target" value={target} onChange={(event) => setTarget(event.target.value)} placeholder="https://mcp.example.net/mcp or 192.0.2.18" /></div>
              <div className="space-y-1"><Label htmlFor="mig-network-port">Port (for host/IP)</Label><Input id="mig-network-port" type="number" min="1" max="65535" value={port} onChange={(event) => setPort(event.target.value)} placeholder="443" /></div>
              <div className="space-y-1 sm:col-span-3"><Label htmlFor="mig-network-scopes">Requested approved scope(s)</Label><Textarea id="mig-network-scopes" rows={2} value={scope} onChange={(event) => setScope(event.target.value)} placeholder="One configured scope per line" /><p className="text-xs text-muted-foreground">Only scopes already approved by tenant configuration are honored. No range or wildcard is added by this form.</p></div>
            </div>
            {scanMutation.error && <div role="alert" className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm">{scanMutation.error.message}</div>}
            <Button disabled={!validScanTarget || !scope.trim() || scanMutation.isPending} onClick={() => scanMutation.mutate()}>
              {scanMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Search className="mr-2 h-4 w-4" />}
              {scanMutation.isPending ? "Scanning approved target…" : "Scan target"}
            </Button>
            {scanMutation.isPending && <div className="space-y-2" role="status"><div className="h-3 w-1/3 animate-pulse rounded bg-muted" /><div className="h-12 animate-pulse rounded bg-muted/70" /></div>}
            {scanResult && <ScanCandidates result={scanResult} />}
          </div>}
        </>}
      </CardContent>
    </Card>}

    {loadError && <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm" role="alert">
      <span>{loadError instanceof Error ? loadError.message : "Could not load tenant clients."}</span>
      <Button size="sm" variant="outline" onClick={refresh}><RefreshCw className="mr-2 h-4 w-4" />Retry</Button>
    </div>}
    {associationError && <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-amber-600/30 bg-amber-500/5 p-3 text-sm" role="alert">
      <span>Client inventory is available, but canonical registration links could not be loaded. Restrictions may be unavailable.</span>
      <Button size="sm" variant="outline" onClick={refresh}><RefreshCw className="mr-2 h-4 w-4" />Retry links</Button>
    </div>}
    <Card>
      <CardContent className="p-0">
        {isLoading ? <LoadingRows /> : loadError ? (
          <div className="px-5 py-8 text-center text-sm text-muted-foreground">Client inventory is unavailable until its tenant lists load successfully. Use Retry above.</div>
        ) : (clientsQuery.data?.length ?? 0) + legacyAgents.length === 0 ? (
          <div className="px-5 py-12 text-center">
            <Users className="mx-auto h-8 w-8 text-muted-foreground/60" />
            <h3 className="mt-3 text-sm font-medium">No tenant-visible clients</h3>
            <p className="mx-auto mt-1 max-w-md text-sm text-muted-foreground">Use Discover to test a known endpoint or scan a single approved network target.</p>
            <Button className="mt-4" variant="outline" onClick={() => setDiscoverOpen(true)}>Open discovery</Button>
          </div>
        ) : <div className="divide-y">
          {(clientsQuery.data ?? []).map((client) => {
            const candidate = candidateByComponent.get(client.component_id);
            const matchedAgent = agentById.get(client.component_id);
            return <button type="button" key={`client:${client.component_id}`} onClick={() => selectClient(client)} className="flex w-full flex-wrap items-center justify-between gap-3 p-4 text-left hover:bg-muted/30">
              <span className="min-w-0 flex-1"><span className="block truncate text-sm font-medium">{client.display_name || client.identity || client.component_id}</span><span className="mt-1 block truncate font-mono text-xs text-muted-foreground">{client.component_id}</span></span>
              <span className="flex items-center gap-2"><span className="rounded-sm bg-muted px-2 py-1 text-xs">{client.client_class || "Client"}</span>{client.client_class?.toUpperCase() === "AGENT" && matchedAgent && <span className="text-xs text-primary">Agent controls available</span>}<span className="text-xs text-muted-foreground">{client.status || client.lifecycle_status || candidate?.status || matchedAgent?.status || "Status unknown"}</span></span>
            </button>;
          })}
          {legacyAgents.map((agent) => <button type="button" key={`agent:${agent.agentId}`} onClick={() => selectAgent(agent)} className="flex w-full flex-wrap items-center justify-between gap-3 p-4 text-left hover:bg-muted/30">
            <span className="min-w-0 flex-1"><span className="block truncate text-sm font-medium">{agent.displayName || agent.agentId}</span><span className="mt-1 block truncate font-mono text-xs text-muted-foreground">{agent.agentId}</span></span>
            <span className="flex items-center gap-2"><span className="rounded-sm bg-muted px-2 py-1 text-xs">Legacy agent</span><span className="text-xs text-muted-foreground">{agent.status || "Status unknown"}</span></span>
          </button>)}
        </div>}
      </CardContent>
    </Card>
  </div>;
}

function CountBox({ label, value, loading, error }: { label: string; value?: number; loading: boolean; error: boolean }) {
  return <div className="rounded-md border bg-card px-3 py-2">
    <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
    <p className="mt-1 font-mono text-lg">{loading ? <span className="inline-block h-5 w-8 animate-pulse rounded bg-muted" /> : error ? "—" : value ?? 0}</p>
  </div>;
}

function ScanCandidates({ result }: { result: ScanResult }) {
  const candidates = result.candidates ?? (result.candidate ? [result.candidate] : []);
  const rejected: unknown[] = result.rejected_scopes ?? result.scope_rejections ?? [];
  const failures = result.failures ?? result.failure_details ?? [];
  return <section className="rounded-md border p-3" data-testid="mig-network-scan-result">
    <div className="flex flex-wrap justify-between gap-2"><h3 className="text-sm font-medium">Scan result</h3><span className="font-mono text-xs text-muted-foreground">{candidates.length} candidate{candidates.length === 1 ? "" : "s"}</span></div>
    {rejected.length > 0 && <div className="mt-3 rounded-md border border-amber-600/30 bg-amber-500/5 p-3 text-sm"><p className="font-medium">Scope rejections</p><ul className="mt-1 list-inside list-disc break-all text-muted-foreground">{rejected.map((item, index) => <li key={`${index}-${typeof item === "string" ? item : "detail"}`}>{typeof item === "string" ? item : JSON.stringify(item)}</li>)}</ul></div>}
    {failures.length > 0 ? <div className="mt-3 rounded-md border p-3 text-sm"><p className="font-medium">Returned failure details</p><ul className="mt-1 list-inside list-disc break-all text-muted-foreground">{failures.map((item, index) => <li key={`failure-${index}`}>{typeof item === "string" ? item : JSON.stringify(item)}</li>)}</ul></div> : <p className="mt-3 text-xs text-muted-foreground">This scan response does not include per-target failure details, so MIG cannot explain individual connection failures from this result.</p>}
    {candidates.length ? <ul className="mt-3 divide-y rounded-md border">{candidates.map((item, index) => <li key={item.candidate_id || `${item.component_id}-${index}`} className="p-3">
      <p className="break-words text-sm font-medium">{item.identity || item.component_id || "Candidate"}</p>
      <p className="mt-1 break-all font-mono text-xs text-muted-foreground">{item.endpoint || item.component_id || "No endpoint reported"}</p>
      <p className="mt-1 text-xs text-muted-foreground">Candidate {item.candidate_id || "ID not returned"} · principal {item.principal_id || "not returned"} · {item.status || "not registered"}</p>
    </li>)}</ul> : <p className="mt-3 text-sm text-muted-foreground">No candidates were returned for this approved target.</p>}
    <p className="mt-3 text-xs text-muted-foreground">Candidates remain unregistered. Discovery does not create permissions.</p>
  </section>;
}

function LegacyAgentEditor({ agent, onSave, onStatus, saving, statusPending, error, scopeSaved, statusSaved }: {
  agent: Agent;
  onSave: (body: Record<string, unknown>) => void;
  onStatus: (status: string) => void;
  saving: boolean;
  statusPending: boolean;
  error: Error | null;
  scopeSaved: boolean;
  statusSaved: boolean;
}) {
  const [intents, setIntents] = useState((agent.allowedIntents ?? []).join("\n"));
  const [riskZones, setRiskZones] = useState((agent.allowedRiskZones ?? []).join(", "));
  const [classification, setClassification] = useState(agent.maxCapabilityClassification || "read_only");
  const [humanApproval, setHumanApproval] = useState(Boolean(agent.requiresHumanApproval));
  const [status, setStatus] = useState(agent.status || "active");
  const credentialIntents = agent.credentialAuthority?.allowedIntents ?? [];
  const applyStatus = () => {
    if (status === "revoked" && !window.confirm(
      `Revoke ${agent.displayName || agent.agentId}? Its access will stop working.`,
    )) return;
    onStatus(status);
  };
  return <div className="space-y-4">
    <div className="rounded-md border bg-muted/20 p-3">
      <p className="flex items-center gap-2 text-sm font-medium"><Shield className="h-4 w-4" />Credential ceiling (read only)</p>
      <p className="mt-1 text-xs text-muted-foreground">Credential authority is separate from this agent’s operating scope.</p>
      <p className="mt-2 break-words text-xs">Intents: {credentialIntents.length ? credentialIntents.join(", ") : "Not reported"} · Risk zone: {String(agent.credentialAuthority?.maxRiskZone || "Not reported")} · Classification: {String(agent.credentialAuthority?.maxCapabilityClassification || "Not reported")}</p>
    </div>
    <div className="grid gap-3 sm:grid-cols-2">
      <div className="space-y-1 sm:col-span-2"><Label htmlFor="mig-agent-intents">Allowed intents — one per line</Label><Textarea id="mig-agent-intents" rows={3} value={intents} onChange={(event) => setIntents(event.target.value)} /></div>
      <div className="space-y-1"><Label htmlFor="mig-agent-risk-zones">Allowed risk zones</Label><Input id="mig-agent-risk-zones" value={riskZones} onChange={(event) => setRiskZones(event.target.value)} placeholder="low, medium" /></div>
      <div className="space-y-1"><Label htmlFor="mig-agent-classification">Maximum capability classification</Label><Input id="mig-agent-classification" value={classification} onChange={(event) => setClassification(event.target.value)} /></div>
      <label className="flex items-center gap-2 text-sm sm:col-span-2"><input type="checkbox" checked={humanApproval} onChange={(event) => setHumanApproval(event.target.checked)} className="accent-primary" />Require human approval</label>
    </div>
    {error && <p role="alert" className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm">{error.message}</p>}
    {scopeSaved && <p role="status" className="text-sm text-primary">Scope restrictions saved.</p>}
    {statusSaved && <p role="status" className="text-sm text-primary">Agent status updated.</p>}
    <div className="flex flex-wrap items-end gap-2 border-t pt-4">
      <Button disabled={saving} onClick={() => onSave({
        allowedIntents: [...new Set(intents.split(/[\n,]/).map((value) => value.trim()).filter(Boolean))],
        allowedRiskZones: [...new Set(riskZones.split(/[\n,]/).map((value) => value.trim()).filter(Boolean))],
        maxCapabilityClassification: classification.trim(),
        requiresHumanApproval: humanApproval,
      })}>{saving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}Save scope restrictions</Button>
      <div className="ml-auto flex items-center gap-2"><Label htmlFor="mig-agent-status" className="text-xs">Status</Label><select id="mig-agent-status" className="h-9 rounded-md border bg-background px-2 text-sm" value={status} onChange={(event) => setStatus(event.target.value)}><option value="active">Active</option><option value="suspended">Suspended</option><option value="revoked">Revoked</option></select><Button variant="outline" disabled={statusPending || status === agent.status} onClick={applyStatus}>{statusPending ? "Updating…" : "Set status"}</Button></div>
    </div>
  </div>;
}
