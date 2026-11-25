import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Building2, CheckCircle2, Eye, GitBranch, KeyRound, Loader2, Network, RefreshCw, ShieldCheck } from "lucide-react";
import { fetchWithAuth } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

type MigMode = "full_control_plane" | "enterprise_intelligence_plane";
type Plane = {
  config: { deploymentMode: MigMode; authorityProvider: string; executionFabric: string; providerTenantRef: string | null; maximumSnapshotAgeSeconds: number };
  provider: { display_name: string; tenant_ref: string | null; state: string; supported: boolean };
  sync: { state: string; last_observed_at: string | null; expires_at: string | null; snapshots: number; projected_principals: number; projected_capabilities: number };
  policy: { state: string; version: string | null; authorization_records: number; denied_records: number };
  estate: Array<{ component_id: string; identity: string; ownership: string; eligibility_source: string; status: string; journey_usage: number; governed_risk: string }>;
};
type JourneySummary = { journey_id: string; origin_agent_id: string; root_intent: string; current_intent: string; hop_count: number; authorization_state: string; temperature: string; created_at: string };
type JourneyDetail = {
  journey: { journeyId: string; originUserId: string; originAgentId: string; rootIntent: string };
  calls: Array<{ callId: string; parentCallId?: string | null; currentIntent: string; callerComponentId: string; targetComponentId: string; outcome?: { outcome: string; reason: string; effectiveAuthority?: Record<string, unknown>; accumulatedState?: Record<string, unknown>; journeyState?: string } }>;
  authorityNodes: Array<{ call_id: string; caller: string; requested: { intent: string; target_component_id: string }; credential: { class: string; allowed_capabilities: string[]; risk_zone_ceiling: string }; authority_source?: { provider: string; reference: string | null; observed_at: string | null; expires_at: string | null }; journey_authority: { root_intent: string; lineage_valid: boolean }; final_authorization: { decision: string; reason?: string } }>;
};
type ObservationMetric = { value: number; journey_ids: string[] };
type ObservationJourney = {
  journey_id: string; journey_version_id: string; origin: string; intent: string; agent: string;
  mcp_path: string[]; accumulated_capabilities: Array<{ capability_id: string; tool_name: string; canonical_service: string; semantic_action: string }>;
  resources: string[]; evidence_quality: string; translated_structural_state: string; temperature: string; status: string;
  correlation_status: string; created_at: string;
  factual_graph: { nodes: Array<{ id: string; evidence_class: string }>; edges: Array<{ id: string; from_ref: string; to_ref: string; relation: string; evidence_class: string }> };
  consequence_overlay: { condition_ref?: string | null; state: string; explanation: string; would_have_blocked: boolean | "UNKNOWN"; proof_state: string };
};
type ObservationExperience = {
  operating_mode: "observe"; mode_explanation: string; evidence_freshness: string;
  summary: Record<string, ObservationMetric>; journeys: ObservationJourney[];
  uncorrelated_observations: Array<{ observation_event_id: string; correlation_status: string }>;
};

const label = (mode: MigMode) => mode === "full_control_plane" ? "Full Control Plane" : "Enterprise Intelligence Plane";
const stateClass = (state: string) => state === "active" || state === "synced" || state === "verified" || state === "healthy" || state === "not_applicable"
  ? "bg-green-500/15 text-green-700" : state === "stale" || state === "incomplete" ? "bg-amber-500/15 text-amber-700" : "bg-red-500/15 text-red-700";

export function MigModeBadge({ plane, loading }: { plane?: Plane; loading: boolean }) {
  if (loading) return <Badge variant="outline"><Loader2 className="mr-1 h-3 w-3 animate-spin" /> Loading mode</Badge>;
  if (!plane) return <Badge className="bg-red-500/15 text-red-700">Mode unavailable</Badge>;
  return <Badge data-testid="badge-mig-mode" className={plane.config.deploymentMode === "full_control_plane" ? "bg-blue-500/15 text-blue-700" : "bg-violet-500/15 text-violet-700"}>{label(plane.config.deploymentMode)}</Badge>;
}

export function useMigControlPlane() {
  return useQuery<Plane>({
    queryKey: ["/api/mig/admin/control-plane"],
    queryFn: async () => {
      const response = await fetchWithAuth("/api/mig/admin/control-plane");
      if (!response.ok) throw new Error((await response.text()) || "Control plane unavailable");
      return response.json();
    },
  });
}

export function MigModeSetup({ plane }: { plane: Plane }) {
  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState<MigMode>(plane.config.deploymentMode);
  const [tenantRef, setTenantRef] = useState(plane.config.providerTenantRef ?? "");
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const mutation = useMutation({
    mutationFn: async () => {
      const enterprise = mode === "enterprise_intelligence_plane";
      const response = await fetchWithAuth("/api/mig/admin/control-plane/mode", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          deployment_mode: mode,
          authority_provider: enterprise ? "microsoft_entra" : "mig_native",
          execution_fabric: enterprise ? "enterprise_managed" : "mig_managed",
          provider_tenant_ref: enterprise ? tenantRef : undefined,
        }),
      });
      if (!response.ok) throw new Error((await response.text()) || "Mode update failed");
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/control-plane"] });
      setOpen(false);
      toast({ title: "MIG operating mode updated", description: `${label(mode)} is now the tenant operating mode.` });
    },
    onError: (error: Error) => toast({ title: "Mode update failed", description: error.message, variant: "destructive" }),
  });
  return <>
    <Button variant="outline" size="sm" onClick={() => setOpen(true)} data-testid="button-configure-mig-mode">Configure mode</Button>
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent data-testid="dialog-mig-mode-setup">
        <DialogHeader><DialogTitle>MIG operating mode</DialogTitle></DialogHeader>
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground">Changing mode changes which control plane supplies authority. Existing journey evidence is retained.</p>
          <div className="space-y-2"><Label>Operating mode</Label>
            <Select value={mode} onValueChange={value => setMode(value as MigMode)}><SelectTrigger data-testid="select-mig-mode"><SelectValue /></SelectTrigger><SelectContent>
              <SelectItem value="full_control_plane">Full Control Plane</SelectItem>
              <SelectItem value="enterprise_intelligence_plane">Enterprise Intelligence Plane</SelectItem>
            </SelectContent></Select>
          </div>
          {mode === "enterprise_intelligence_plane" && <div className="space-y-2"><Label htmlFor="provider-tenant">Microsoft Entra tenant reference</Label><Input id="provider-tenant" value={tenantRef} onChange={event => setTenantRef(event.target.value)} data-testid="input-provider-tenant" /></div>}
          <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-xs text-amber-900"><AlertTriangle className="mr-1 inline h-3.5 w-3.5" />This does not edit groups, roles, entitlements, OAuth, or Conditional Access in the enterprise provider.</div>
          <Button onClick={() => mutation.mutate()} disabled={mutation.isPending || (mode === "enterprise_intelligence_plane" && !tenantRef.trim())} data-testid="button-confirm-mig-mode">
            {mutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}Confirm operating mode
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  </>;
}

function ExplicitState({ state }: { state: string }) {
  return <Badge className={stateClass(state)} data-testid={`badge-plane-state-${state}`}>{state.replaceAll("_", " ")}</Badge>;
}

const observationMetricLabels: Record<string, string> = {
  agents: "Agents", mcps: "MCPs", capabilities: "Capabilities", journeys: "Journeys",
  cross_mcp_journeys: "Cross-MCP journeys", consequential_paths: "Consequential paths",
  would_have_blocked: "Would have blocked", insufficient_evidence: "Insufficient evidence",
};

function ObservationStatus({ status }: { status: string }) {
  const classes: Record<string, string> = {
    observed: "bg-blue-500/15 text-blue-700", governed: "bg-violet-500/15 text-violet-700",
    would_have_blocked: "bg-amber-500/15 text-amber-800", blocked: "bg-red-500/15 text-red-700",
    insufficient_evidence: "bg-slate-500/15 text-slate-700",
  };
  return <Badge className={classes[status] ?? "bg-slate-500/15 text-slate-700"} data-testid={`badge-observation-${status}`}>{status.replaceAll("_", " ")}</Badge>;
}

export function ObservationWorkspace() {
  const [selectedId, setSelectedId] = useState("");
  const [filterIds, setFilterIds] = useState<string[] | null>(null);
  const [filterKey, setFilterKey] = useState<string | null>(null);
  const [feedbackOpen, setFeedbackOpen] = useState(false);
  const [readinessOpen, setReadinessOpen] = useState(false);
  const [disposition, setDisposition] = useState("confirmed");
  const [note, setNote] = useState("");
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const query = useQuery<ObservationExperience>({
    queryKey: ["/api/mig/admin/observations"],
    queryFn: async () => {
      const response = await fetchWithAuth("/api/mig/admin/observations");
      if (!response.ok) throw new Error((await response.text()) || "Observation experience unavailable");
      return response.json();
    },
  });
  const selected = query.data?.journeys.find(journey => journey.journey_id === selectedId);
  const postOutcome = useMutation({
    mutationFn: async ({ kind }: { kind: "feedback" | "enforcement-readiness" }) => {
      if (!selected) throw new Error("Select a journey");
      const response = await fetchWithAuth(`/api/mig/admin/observations/journeys/${encodeURIComponent(selected.journey_id)}/${kind}`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(kind === "feedback"
          ? { journey_version_id: selected.journey_version_id, disposition, note }
          : { journey_version_id: selected.journey_version_id, condition_ref: selected.consequence_overlay.condition_ref, confirmed: true }),
      });
      if (!response.ok) throw new Error((await response.text()) || "Outcome could not be recorded");
      return { kind, result: await response.json() };
    },
    onSuccess: ({ kind }) => {
      queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/observations"] });
      setFeedbackOpen(false); setReadinessOpen(false); setNote("");
      toast({ title: kind === "feedback" ? "Feedback recorded" : "Selection recorded for policy review",
        description: "No policy, graph, or enforcement setting was changed." });
    },
    onError: (error: Error) => toast({ title: "Could not record selection", description: error.message, variant: "destructive" }),
  });
  if (query.isLoading) return <div className="flex items-center gap-2 py-10 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" />Loading observed journeys…</div>;
  if (query.isError || !query.data) return <div className="rounded-md border border-red-300 bg-red-50 p-4 text-sm text-red-800" data-testid="observation-error">Observation evidence is unavailable. No health or authority is being assumed.</div>;
  const visible = filterIds ? query.data.journeys.filter(journey => filterIds.includes(journey.journey_id)) : query.data.journeys;
  return <div className="space-y-4" data-testid="observation-workspace">
    <Card className="border-violet-300 bg-violet-50/50" data-testid="observe-mode-banner"><CardContent className="flex gap-3 pt-5">
      <Eye className="mt-0.5 h-5 w-5 text-violet-700" /><div><strong>Observe mode</strong><p className="text-sm text-muted-foreground">{query.data.mode_explanation}</p></div>
    </CardContent></Card>
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      {Object.entries(observationMetricLabels).map(([key, text]) => {
        const metric = query.data.summary[key];
        return <button key={key} type="button" className="rounded-lg border bg-card p-4 text-left hover:border-primary disabled:cursor-default"
          disabled={!metric} onClick={() => { setFilterIds(metric?.journey_ids ?? []); setFilterKey(key); }} data-testid={`metric-${key}`}>
          <div className="text-2xl font-semibold">{metric ? metric.value : "Unavailable"}</div><div className="text-xs text-muted-foreground">{text}</div>
          <div className="mt-2 text-xs text-primary">{metric?.journey_ids.length ? "View supporting journeys" : "No supporting journey available"}</div>
        </button>;
      })}
    </div>
    {filterIds && <Button variant="ghost" size="sm" onClick={() => { setFilterIds(null); setFilterKey(null); }} data-testid="clear-observation-filter">Show all journeys</Button>}
    {filterKey === "insufficient_evidence" && query.data.uncorrelated_observations.length > 0 && <Card data-testid="uncorrelated-observations"><CardHeader><CardTitle className="text-base">Observations without sufficient correlation</CardTitle></CardHeader><CardContent className="space-y-2">
      {query.data.uncorrelated_observations.map(item => <div key={item.observation_event_id} className="rounded border p-2 text-sm"><span className="font-mono text-xs">{item.observation_event_id}</span><div className="text-muted-foreground">{item.correlation_status.replaceAll("_", " ")}</div></div>)}
    </CardContent></Card>}
    <Card><CardHeader><CardTitle className="flex items-center gap-2 text-base"><GitBranch className="h-4 w-4" /> Observed agentic journeys</CardTitle></CardHeader><CardContent>
      {!visible.length ? <p className="py-8 text-center text-sm text-muted-foreground">No journeys support this view. Uncorrelated observations remain insufficient evidence and are not turned into journey links.</p> :
      <div className="overflow-x-auto"><Table><TableHeader><TableRow><TableHead>Status</TableHead><TableHead>Origin / agent</TableHead><TableHead>Intent</TableHead><TableHead>MCP path</TableHead><TableHead>Capabilities / resources</TableHead><TableHead>Evidence</TableHead><TableHead>Structural state</TableHead><TableHead>Temperature</TableHead></TableRow></TableHeader><TableBody>
        {visible.map(row => <TableRow key={row.journey_id} className="cursor-pointer align-top" onClick={() => setSelectedId(row.journey_id)} data-testid={`row-observed-journey-${row.journey_id}`}>
          <TableCell><ObservationStatus status={row.status} /></TableCell><TableCell>{row.origin}<div className="text-xs text-muted-foreground">{row.agent}</div></TableCell>
          <TableCell>{row.intent}</TableCell><TableCell>{row.mcp_path.join(" → ") || "Unavailable"}</TableCell>
          <TableCell>{row.accumulated_capabilities.map(cap => cap.capability_id).join(", ") || "Unknown"}<div className="text-xs text-muted-foreground">{row.resources.join(", ") || "No resources supplied"}</div></TableCell>
          <TableCell>{row.evidence_quality}<div className="text-xs">{row.correlation_status.replaceAll("_", " ")}</div></TableCell>
          <TableCell>{row.translated_structural_state}</TableCell><TableCell>{row.temperature}</TableCell>
        </TableRow>)}
      </TableBody></Table></div>}
    </CardContent></Card>
    {selected && <Card data-testid="observed-journey-detail"><CardHeader><CardTitle className="text-base">Journey evidence and consequence</CardTitle></CardHeader><CardContent className="space-y-5">
      <div className="grid gap-4 md:grid-cols-2">
        <section className="rounded-md border p-4" data-testid="factual-execution-graph"><h3 className="font-semibold">Factual execution graph</h3><p className="mb-3 text-xs text-muted-foreground">Only persisted, evidence-bound nodes and relationships appear here.</p>
          {!selected.factual_graph.edges.length ? <p className="text-sm text-muted-foreground">No factual graph links are available.</p> :
            <div className="space-y-2">{selected.factual_graph.edges.map(edge => <div key={edge.id} className="rounded border p-2 text-sm"><Badge variant="outline">Observed fact</Badge><div className="mt-1 font-mono text-xs">{edge.from_ref} → {edge.to_ref}</div><div>{edge.relation}</div></div>)}</div>}
        </section>
        <section className="rounded-md border border-violet-300 bg-violet-50/40 p-4" data-testid="consequence-overlay"><h3 className="font-semibold">Consequence overlay</h3><p className="mb-3 text-xs text-muted-foreground">Server-produced interpretation; it does not add or rebuild graph links.</p>
          <ObservationStatus status={selected.status} /><p className="mt-3 text-sm">{selected.consequence_overlay.explanation}</p>
          {selected.consequence_overlay.state === "compositionally_consequential" && <p className="mt-3 rounded border border-amber-300 bg-amber-50 p-3 text-sm font-medium" data-testid="composition-explanation">Each observed access may be legitimate on its own, while the accumulated path is consequential when composed.</p>}
          <p className="mt-2 text-xs text-muted-foreground">Proof: {selected.consequence_overlay.proof_state}</p>
        </section>
      </div>
      <div className="flex flex-wrap gap-2"><Button variant="outline" onClick={() => setFeedbackOpen(true)} data-testid="button-review-finding">Review finding</Button>
        <Button onClick={() => setReadinessOpen(true)}
          disabled={!["governed", "would_have_blocked"].includes(selected.status) || selected.consequence_overlay.proof_state !== "available" || !selected.consequence_overlay.condition_ref}
          data-testid="button-begin-enforcement-readiness">Begin Observe-to-Enforce selection</Button></div>
    </CardContent></Card>}
    <Dialog open={feedbackOpen} onOpenChange={setFeedbackOpen}><DialogContent><DialogHeader><DialogTitle>Record finding feedback</DialogTitle></DialogHeader>
      <p className="text-sm text-muted-foreground">Feedback is an append-only review record. It does not become policy or alter the graph.</p>
      <Select value={disposition} onValueChange={setDisposition}><SelectTrigger data-testid="select-feedback-disposition"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="confirmed">Confirmed</SelectItem><SelectItem value="disputed">Disputed</SelectItem><SelectItem value="needs_more_evidence">Needs more evidence</SelectItem></SelectContent></Select>
      <textarea className="min-h-24 rounded-md border bg-background p-2 text-sm" maxLength={500} value={note} onChange={event => setNote(event.target.value)} aria-label="Feedback note" />
      <Button onClick={() => postOutcome.mutate({ kind: "feedback" })} data-testid="button-submit-feedback">Record feedback</Button>
    </DialogContent></Dialog>
    <Dialog open={readinessOpen} onOpenChange={setReadinessOpen}><DialogContent><DialogHeader><DialogTitle>Confirm enforcement-readiness selection</DialogTitle></DialogHeader>
      <div className="rounded border border-amber-300 bg-amber-50 p-3 text-sm">This records the selected observed condition for deliberate policy review. Enforcement remains off; no rule, authority, IAM setting, or graph link is created.</div>
      <Button onClick={() => postOutcome.mutate({ kind: "enforcement-readiness" })} data-testid="button-confirm-enforcement-readiness">Confirm selection only</Button>
    </DialogContent></Dialog>
  </div>;
}

export function EnterpriseControlPlane({ plane }: { plane: Plane }) {
  return <div className="grid gap-4 md:grid-cols-2">
    <Card data-testid="card-enterprise-provider"><CardHeader><CardTitle className="flex items-center gap-2 text-base"><Building2 className="h-4 w-4" /> Enterprise Control Plane</CardTitle></CardHeader><CardContent className="space-y-3 text-sm">
      <div className="flex justify-between"><span>Provider</span><span className="font-medium">{plane.provider.display_name}</span></div>
      <div className="flex justify-between"><span>Provider tenant</span><span className="font-mono text-xs">{plane.provider.tenant_ref ?? "Not configured"}</span></div>
      <div className="flex justify-between"><span>Connection</span><ExplicitState state={!plane.provider.supported ? "unsupported_provider" : plane.provider.state} /></div>
      <p className="border-t pt-3 text-xs text-muted-foreground">Read-only visibility. Identity and access administration remains in the enterprise control plane.</p>
    </CardContent></Card>
    <Card data-testid="card-authority-sync"><CardHeader><CardTitle className="flex items-center gap-2 text-base"><RefreshCw className="h-4 w-4" /> Authority Sync</CardTitle></CardHeader><CardContent className="space-y-3 text-sm">
      <div className="flex justify-between"><span>Status</span><ExplicitState state={plane.sync.state} /></div>
      <div className="flex justify-between"><span>Last observation</span><span>{plane.sync.last_observed_at ? new Date(plane.sync.last_observed_at).toLocaleString() : "No synchronized authority"}</span></div>
      <div className="grid grid-cols-3 gap-2 text-center"><div className="rounded border p-2"><strong>{plane.sync.snapshots}</strong><div className="text-xs text-muted-foreground">Snapshots</div></div><div className="rounded border p-2"><strong>{plane.sync.projected_principals}</strong><div className="text-xs text-muted-foreground">Principals</div></div><div className="rounded border p-2"><strong>{plane.sync.projected_capabilities}</strong><div className="text-xs text-muted-foreground">Capabilities</div></div></div>
      <div className="flex justify-between border-t pt-3"><span>Policy health</span><ExplicitState state={plane.policy.state} /></div>
    </CardContent></Card>
  </div>;
}

export function McpEstate({ plane }: { plane: Plane }) {
  return <Card><CardHeader><CardTitle className="flex items-center gap-2 text-base"><Network className="h-4 w-4" /> MCP Estate</CardTitle></CardHeader><CardContent>
    {plane.estate.length === 0 ? <p className="py-8 text-center text-sm text-muted-foreground">No MCP estate records are available for this tenant.</p> :
    <Table><TableHeader><TableRow><TableHead>MCP</TableHead><TableHead>Ownership</TableHead><TableHead>Eligibility source</TableHead><TableHead>Status</TableHead><TableHead>Journey usage</TableHead><TableHead>Governed risk</TableHead></TableRow></TableHeader><TableBody>
      {plane.estate.map(item => <TableRow key={item.component_id} data-testid={`row-mcp-estate-${item.component_id}`}><TableCell><div>{item.identity}</div><div className="font-mono text-xs text-muted-foreground">{item.component_id}</div></TableCell><TableCell><Badge variant="outline">{item.ownership === "mig_managed" ? "MIG-managed" : "Enterprise-managed"}</Badge></TableCell><TableCell>{item.eligibility_source}</TableCell><TableCell><ExplicitState state={item.status} /></TableCell><TableCell>{item.journey_usage}</TableCell><TableCell>{item.governed_risk}</TableCell></TableRow>)}
    </TableBody></Table>}
  </CardContent></Card>;
}

export function JourneysWorkspace() {
  const [selected, setSelected] = useState("");
  const summaries = useQuery<JourneySummary[]>({ queryKey: ["/api/mig/admin/journeys"], queryFn: async () => {
    const response = await fetchWithAuth("/api/mig/admin/journeys"); if (!response.ok) throw new Error("Journeys unavailable"); return response.json();
  }});
  const detail = useQuery<JourneyDetail>({ queryKey: ["/api/mig/admin/journeys", selected], enabled: !!selected, queryFn: async () => {
    const response = await fetchWithAuth(`/api/mig/admin/journeys/${encodeURIComponent(selected)}`); if (!response.ok) throw new Error("Journey detail unavailable"); return response.json();
  }});
  if (summaries.isLoading) return <div className="flex items-center gap-2 py-10 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" />Loading journeys…</div>;
  if (summaries.isError) return <div className="rounded-md border border-red-300 bg-red-50 p-4 text-sm text-red-800">Journey history is unavailable.</div>;
  return <div className="space-y-4">
    <Card><CardHeader><CardTitle className="flex items-center gap-2 text-base"><GitBranch className="h-4 w-4" /> Journeys</CardTitle></CardHeader><CardContent>
      {!summaries.data?.length ? <p className="py-8 text-center text-sm text-muted-foreground">No governed journeys have been recorded.</p> :
      <Table><TableHeader><TableRow><TableHead>Origin</TableHead><TableHead>Root intent</TableHead><TableHead>Current intent</TableHead><TableHead>Hops</TableHead><TableHead>Temperature</TableHead><TableHead>Authorization</TableHead></TableRow></TableHeader><TableBody>
        {summaries.data.map(row => <TableRow key={row.journey_id} className="cursor-pointer" onClick={() => setSelected(row.journey_id)} data-testid={`row-journey-${row.journey_id}`}><TableCell>{row.origin_agent_id}</TableCell><TableCell>{row.root_intent}</TableCell><TableCell>{row.current_intent}</TableCell><TableCell>{row.hop_count}</TableCell><TableCell><Badge variant="outline">{row.temperature}</Badge></TableCell><TableCell><ExplicitState state={row.authorization_state} /></TableCell></TableRow>)}
      </TableBody></Table>}
    </CardContent></Card>
    {selected && <Card data-testid="card-journey-detail"><CardHeader><CardTitle className="text-base">Journey detail</CardTitle></CardHeader><CardContent>
      {detail.isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : detail.isError || !detail.data ? <p className="text-sm text-red-700">This journey detail is unavailable.</p> :
      <div className="space-y-4">
        <div className="grid gap-2 text-sm md:grid-cols-3"><div><span className="text-muted-foreground">Origin</span><div>{detail.data.journey.originAgentId} / {detail.data.journey.originUserId}</div></div><div><span className="text-muted-foreground">Root intent</span><div>{detail.data.journey.rootIntent}</div></div><div><span className="text-muted-foreground">Current intent</span><div>{detail.data.calls.at(-1)?.currentIntent ?? detail.data.journey.rootIntent}</div></div></div>
        <div className="space-y-2">{detail.data.authorityNodes.map((node, index) => {
          const call = detail.data!.calls.find(item => item.callId === node.call_id);
          const effective = call?.outcome?.effectiveAuthority ?? {};
          const accumulated = call?.outcome?.accumulatedState ?? {};
          return <div key={node.call_id} className="rounded-md border p-3 text-sm" data-testid={`journey-hop-${index}`}>
            <div className="mb-2 flex items-center justify-between"><strong>Hop {index + 1}: {node.caller} → {node.requested.target_component_id}</strong><ExplicitState state={node.final_authorization.decision} /></div>
            <div className="grid gap-2 md:grid-cols-3"><div><span className="text-muted-foreground">Authority source</span><div>{node.authority_source?.provider ?? "unavailable"} / {node.credential.class}</div><div className="text-xs text-muted-foreground">ceiling {node.credential.risk_zone_ceiling}</div></div><div><span className="text-muted-foreground">Intent legitimacy</span><div>{node.requested.intent} · {node.journey_authority.lineage_valid ? "lineage verified" : "lineage incomplete"}</div></div><div><span className="text-muted-foreground">Governed reading</span><div>{call?.outcome?.reason ?? "No translated reading available"}</div></div></div>
            <div className="mt-2 flex flex-wrap gap-2 text-xs"><Badge variant="outline">Temperature {call?.outcome?.journeyState ?? "COOL"}</Badge><Badge variant="outline">Capabilities {Array.isArray((accumulated as any).admitted_capability_ids) ? (accumulated as any).admitted_capability_ids.join(", ") || "none accumulated" : String((effective as any).capabilityId ?? "not available")}</Badge></div>
          </div>;
        })}</div>
      </div>}
    </CardContent></Card>}
  </div>;
}

export function FullControlSummary({ plane }: { plane: Plane }) {
  return <div className="grid gap-3 md:grid-cols-3"><Card><CardContent className="pt-5"><KeyRound className="mb-2 h-5 w-5 text-blue-600" /><strong>MIG-managed authority</strong><p className="mt-1 text-xs text-muted-foreground">Credentials, ceilings, registration requests, discovery, and policies remain locally governed.</p></CardContent></Card><Card><CardContent className="pt-5"><ShieldCheck className="mb-2 h-5 w-5 text-green-600" /><strong>Policy health</strong><div className="mt-2"><ExplicitState state={plane.policy.state} /></div></CardContent></Card><Card><CardContent className="pt-5"><CheckCircle2 className="mb-2 h-5 w-5 text-violet-600" /><strong>{plane.policy.authorization_records}</strong><p className="mt-1 text-xs text-muted-foreground">Recorded authorization decisions</p></CardContent></Card></div>;
}