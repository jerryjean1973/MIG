/**
 * MIG (MCP Intent Gateway) Admin Page — /mig
 *
 * Operator surface for the pre-execution intent authorization / capability
 * exposure gateway that sits in front of the BRIPe MCP interface.
 *
 * MIG governs identity, declared intent, capability exposure, and audit
 * only — no BRIPe scoring/decision logic is rendered or configured here.
 *
 * Tabs:
 *   - MCP Clients: import/suspend/delete external MCP callers
 *   - Intent Libraries: bripe-core-v1 seed + any tenant-authored libraries
 *   - Audit Log: every discover/execute decision with transition_proof_id
 */

import { useState, useMemo, useEffect, Fragment, type FormEvent } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ShieldCheck, ShieldAlert, ShieldOff, Plus, RefreshCw, Loader2,
  Key, ScrollText, Boxes, CheckCircle2, XCircle, AlertTriangle,
  Radar, FileSearch, GitBranch, Lock, Copy, ChevronDown, ChevronRight,
  KeyRound, ExternalLink, ListChecks, ShieldQuestion, Activity,
  CheckCheck, BarChart3, TrendingUp, ClipboardList,
  FlaskConical, Network, TestTube2, GitMerge, Award, Zap,
  ArrowRight, Info, GitPullRequest, Search, Upload, Server, UserPlus, Eye, ShieldPlus,
} from "lucide-react";
import type { MS5Report, MS5Finding, MS5Grade, MS5CertificationState } from "@shared/ms5-contracts";
import type { MigCredentialAuthorityComparison, MigCredentialAuthorityProjection } from "../../../shared/protocol/shared/mcp-contract-types";
import { useLocation, useSearch } from "wouter";
import { fetchWithAuth } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EnterpriseControlPlane, FullControlSummary, JourneysWorkspace, McpEstate, MigModeBadge, MigModeSetup, ObservationWorkspace, useMigControlPlane } from "@/components/mig-dual-mode";
import { MigSimpleWorkspace } from "@/components/mig-simple-workspace";
import { MigHostOperators } from "@/components/mig-host-operators";

const TENANT_ID = "default";
const TENANT_HEADERS = { "x-tenant-id": TENANT_ID };

async function migPost(url: string, body: unknown): Promise<Response> {
  const res = await fetchWithAuth(url, {
    method: "POST",
    headers: { ...TENANT_HEADERS, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = (await res.text()) || res.statusText;
    throw new Error(`${res.status}: ${text}`);
  }
  return res;
}

interface MigAgent {
  id: number;
  agentId: string;
  displayName: string;
  agentType: string;
  status: "active" | "suspended" | "revoked";
  lifecycleState: "discovery" | "reviewing" | "locked" | "active";
  discoveryExceptionGranted: boolean;
  trustLevel: string;
  allowedRiskZones: string[];
  allowedIntentLibraries: string[];
  allowedIntents?: string[];
  maxCapabilityClassification: string;
  requiresHumanApproval: boolean;
  createdAt: string;
}

interface MigDiscoveryEvent {
  id: number;
  eventId: string;
  agentId: string;
  requestKind: "discover" | "execute";
  toolName?: string;
  capabilityId?: string;
  domainHints: string[];
  createdAt: string;
}

interface MigDraftIntentProfile {
  id: number;
  draftId: string;
  agentId: string;
  proposedName: string;
  proposedDescription: string;
  proposedAllowedToolNames: string[];
  proposedCapabilityIds: string[];
  proposedDomainScope: string[];
  proposedRiskZone: string;
  observedEventCount: number;
  confidence: number;
  policyFindings: Array<{ event_type?: string; tool_name?: string; reason?: string; at?: string }>;
  evidenceSummary: string;
  status: "pending" | "approved" | "rejected";
  resultingIntentId?: string;
  reviewedBy?: string;
  reviewNotes?: string;
  createdAt: string;
  reviewedAt?: string;
}

interface MigDriftEvent {
  id: number;
  eventId: string;
  agentId: string;
  driftType: string;
  toolName?: string;
  detail: string;
  severity: "info" | "warning" | "critical";
  resolved: boolean;
  resolvedBy?: string;
  resolvedAt?: string;
  createdAt: string;
}

interface MigIntentLibrary {
  id: number;
  libraryId: string;
  name: string;
  version: string;
  status: "draft" | "published" | "deprecated";
}

interface MigIntentDefinition {
  id: number;
  intentId: string;
  libraryId: string;
  name: string;
  description: string;
  riskZone: string;
  status: string;
}

interface MigAuditEvent {
  id: number;
  agentId: string;
  intentId?: string;
  eventType: string;
  decision: string;
  reason?: string;
  transitionProofId?: string;
  createdAt: string;
}

type MigClientClassFilter = "all" | "llm" | "mcp";

function migClientClass(agent?: MigAgent): "llm" | "mcp" {
  return agent?.agentType === "external_mcp_client" ? "mcp" : "llm";
}

function ClientClassBadge({ agent }: { agent?: MigAgent }) {
  const clientClass = migClientClass(agent);
  return (
    <Badge variant="outline" className={clientClass === "llm" ? "border-violet-500/40 text-violet-600" : "border-blue-500/40 text-blue-600"}>
      {clientClass === "llm" ? "LLM" : "MCP"}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active: "bg-green-500/15 text-green-600 dark:text-green-400",
    published: "bg-green-500/15 text-green-600 dark:text-green-400",
    allow: "bg-green-500/15 text-green-600 dark:text-green-400",
    suspended: "bg-yellow-500/15 text-yellow-600 dark:text-yellow-400",
    draft: "bg-yellow-500/15 text-yellow-600 dark:text-yellow-400",
    revoked: "bg-red-500/15 text-red-600 dark:text-red-400",
    deny: "bg-red-500/15 text-red-600 dark:text-red-400",
    deprecated: "bg-muted text-muted-foreground",
    discovery: "bg-blue-500/15 text-blue-600 dark:text-blue-400",
    reviewing: "bg-purple-500/15 text-purple-600 dark:text-purple-400",
    locked: "bg-teal-500/15 text-teal-600 dark:text-teal-400",
    pending: "bg-yellow-500/15 text-yellow-600 dark:text-yellow-400",
    approved: "bg-green-500/15 text-green-600 dark:text-green-400",
    rejected: "bg-red-500/15 text-red-600 dark:text-red-400",
    warning: "bg-yellow-500/15 text-yellow-600 dark:text-yellow-400",
    critical: "bg-red-500/15 text-red-600 dark:text-red-400",
    info: "bg-blue-500/15 text-blue-600 dark:text-blue-400",
  };
  return <Badge className={map[status] ?? "bg-muted text-muted-foreground"} data-testid={`badge-status-${status}`}>{status}</Badge>;
}

export default function MigAdminPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [, setLocation] = useLocation();
  const searchString = useSearch();
  const searchParams = useMemo(() => new URLSearchParams(searchString), [searchString]);
  const keyIdParam = searchParams.get("keyId") ?? "";
  const actionParam = searchParams.get("action") ?? "";
  const [simpleMig, setSimpleMig] = useState(() => {
    if (typeof window === "undefined") return true;
    if (searchParams.get("keyId") || searchParams.get("action") === "register") return false;
    try {
      const preference = window.localStorage.getItem("mig-simple-view");
      return preference === null ? true : preference === "true";
    } catch {
      return true;
    }
  });

  const [newAgentOpen, setNewAgentOpen] = useState(false);
  const [mainTab, setMainTab] = useState("journeys");
  const controlPlaneQuery = useMigControlPlane();
  const plane = controlPlaneQuery.data?.config ? controlPlaneQuery.data : undefined;
  const enterpriseMode = plane?.config.deploymentMode === "enterprise_intelligence_plane";
  const [clientClassFilter, setClientClassFilter] = useState<MigClientClassFilter>("all");
  const [discoveryClassFilter, setDiscoveryClassFilter] = useState<MigClientClassFilter>("all");
  const [auditClassFilter, setAuditClassFilter] = useState<MigClientClassFilter>("all");
  const [newLibOpen, setNewLibOpen] = useState(false);
  const [issuedAgentInfo, setIssuedAgentInfo] = useState<{ agentId: string; displayName: string; ticketSecret: string } | null>(null);
  const [expandedIntentsAgent, setExpandedIntentsAgent] = useState<string | null>(null);
  const [expandedIntentsShowAdv, setExpandedIntentsShowAdv] = useState<Record<string, boolean>>({});
  const [agentIntentDraft, setAgentIntentDraft] = useState<Record<string, Set<string>>>({});

  useEffect(() => {
    try {
      window.localStorage.setItem("mig-simple-view", String(simpleMig));
    } catch {
      // Preference storage is optional; endpoint and intent data are never persisted.
    }
  }, [simpleMig]);

  const agentsQuery = useQuery<MigAgent[]>({
    queryKey: ["/api/mig/admin/agents"],
    queryFn: async () => {
      const res = await fetch("/api/mig/admin/agents", { headers: TENANT_HEADERS });
      if (!res.ok) throw new Error("Failed to load agents");
      return res.json();
    },
  });
  const agentsById = useMemo(
    () => new Map((agentsQuery.data ?? []).map((agent) => [agent.agentId, agent])),
    [agentsQuery.data],
  );
  const filterByClientClass = <T extends { agentId: string },>(rows: T[], filter: MigClientClassFilter) =>
    filter === "all" ? rows : rows.filter((row) => migClientClass(agentsById.get(row.agentId)) === filter);
  const visibleAgents = (agentsQuery.data ?? []).filter(
    (agent) => clientClassFilter === "all" || migClientClass(agent) === clientClassFilter,
  );

  useEffect(() => {
    if (actionParam === "register") {
      setSimpleMig(false);
      setMainTab("agents");
      setNewAgentOpen(true);
    }
  }, [actionParam]);

  useEffect(() => {
    if (!keyIdParam) return;
    setSimpleMig(false);
    setMainTab("agents");
    if (!agentsQuery.data || agentsQuery.data.length === 0) return;
    const match = agentsQuery.data.find(
      (a) => a.agentId === keyIdParam || a.agentId.includes(keyIdParam)
    );
    if (match) {
      setExpandedIntentsAgent(match.agentId);
    }
  }, [keyIdParam, agentsQuery.data]);

  const librariesQuery = useQuery<MigIntentLibrary[]>({
    queryKey: ["/api/mig/admin/intent-libraries"],
    queryFn: async () => {
      const res = await fetch("/api/mig/admin/intent-libraries", { headers: TENANT_HEADERS });
      if (!res.ok) throw new Error("Failed to load intent libraries");
      return res.json();
    },
  });

  const intentsQuery = useQuery<MigIntentDefinition[]>({
    queryKey: ["/api/mig/admin/intent-definitions"],
    queryFn: async () => {
      const res = await fetch("/api/mig/admin/intent-definitions", { headers: TENANT_HEADERS });
      if (!res.ok) throw new Error("Failed to load intent definitions");
      return res.json();
    },
  });

  const auditQuery = useQuery<MigAuditEvent[]>({
    queryKey: ["/api/mig/admin/audit"],
    queryFn: async () => {
      const res = await fetch("/api/mig/admin/audit?limit=100", { headers: TENANT_HEADERS });
      if (!res.ok) throw new Error("Failed to load audit log");
      return res.json();
    },
  });

  const mcpKeysQuery = useQuery<Array<{ id: number; tenant_id: string; display_name: string; key_prefix: string; status: string; classification: string; mig_agent_id?: string | null }>>({
    queryKey: ["/api/mcp/admin/keys/all"],
    queryFn: async () => {
      const res = await fetchWithAuth("/api/mcp/admin/keys?all=1", { headers: { "x-tenant-id": "default" } });
      if (!res.ok) return [];
      return res.json();
    },
    staleTime: 30_000,
  });

  function getLinkedMcpKeys(agentId: string) {
    return (mcpKeysQuery.data ?? []).filter((key) => key.mig_agent_id === agentId);
  }

  const linkedKeyIds = useMemo(() => {
    const ids = new Set<number>();
    for (const agent of agentsQuery.data ?? []) {
      for (const k of getLinkedMcpKeys(agent.agentId)) ids.add(k.id);
    }
    return ids;
  }, [agentsQuery.data, mcpKeysQuery.data]);

  const seedMutation = useMutation({
    mutationFn: async () => migPost("/api/mig/admin/seed-defaults", {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/intent-libraries"] });
      queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/intent-definitions"] });
      toast({ title: "Seeded bripe-core-v1 intent library" });
    },
    onError: (e: Error) => toast({ title: "Seed failed", description: e.message, variant: "destructive" }),
  });

  const createAgentMutation = useMutation({
    mutationFn: async (body: Record<string, unknown>) =>
      migPost("/api/mig/admin/agents", body),
    onSuccess: async (res: Response) => {
      const data = await res.json();
      setIssuedAgentInfo({
        agentId: data.agent?.agentId ?? data.agentId ?? "",
        displayName: data.agent?.displayName ?? data.displayName ?? "",
        ticketSecret: data.ticket_secret ?? "",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/agents"] });
      toast({ title: "Agent registered" });
    },
    onError: (e: Error) => toast({ title: "Registration failed", description: e.message, variant: "destructive" }),
  });

  const updateAgentIntentsMutation = useMutation({
    mutationFn: async ({ agentId, intents }: { agentId: string; intents: string[] }) => {
      const res = await fetchWithAuth(`/api/mig/admin/agents/${agentId}`, {
        method: "PATCH",
        headers: { ...TENANT_HEADERS, "Content-Type": "application/json" },
        body: JSON.stringify({ allowedIntents: intents }),
      });
      if (!res.ok) {
        const text = (await res.text()) || res.statusText;
        throw new Error(`${res.status}: ${text}`);
      }
      return res.json();
    },
    onSuccess: (_data, vars) => {
      queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/agents"] });
      toast({ title: "Intent permissions saved", description: `Updated intent access for agent.` });
      setExpandedIntentsAgent(null);
      setAgentIntentDraft(prev => {
        const next = { ...prev };
        delete next[vars.agentId];
        return next;
      });
    },
    onError: (e: Error) => toast({ title: "Failed to save intent permissions", description: e.message, variant: "destructive" }),
  });

  const statusMutation = useMutation({
    mutationFn: async ({ agentId, status }: { agentId: string; status: string }) =>
      migPost(`/api/mig/admin/agents/${agentId}/status`, { status }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/agents"] });
      toast({ title: "Agent status updated" });
    },
    onError: (e: Error) => toast({ title: "Update failed", description: e.message, variant: "destructive" }),
  });

  const toggleIntentMutation = useMutation({
    mutationFn: async ({ intentId, enable }: { intentId: string; enable: boolean }) => {
      const endpoint = enable
        ? `/api/mig/admin/intent-definitions/${intentId}/activate`
        : `/api/mig/admin/intent-definitions/${intentId}/deprecate`;
      const res = await fetch(endpoint, { method: "POST", headers: TENANT_HEADERS });
      if (!res.ok) throw new Error("Failed to update intent status");
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/intent-definitions"] });
      toast({ title: "Intent status updated" });
    },
    onError: (e: Error) => toast({ title: "Toggle failed", description: e.message, variant: "destructive" }),
  });

  const [discoveryAgentId, setDiscoveryAgentId] = useState<string>("");

  const draftsQuery = useQuery<MigDraftIntentProfile[]>({
    queryKey: ["/api/mig/admin/drafts"],
    queryFn: async () => {
      const res = await fetch("/api/mig/admin/drafts", { headers: TENANT_HEADERS });
      if (!res.ok) throw new Error("Failed to load draft profiles");
      return res.json();
    },
  });

  const driftEventsQuery = useQuery<MigDriftEvent[]>({
    queryKey: ["/api/mig/admin/drift-events"],
    queryFn: async () => {
      const res = await fetch("/api/mig/admin/drift-events", { headers: TENANT_HEADERS });
      if (!res.ok) throw new Error("Failed to load drift events");
      return res.json();
    },
  });

  const discoveryEventsQuery = useQuery<MigDiscoveryEvent[]>({
    queryKey: ["/api/mig/admin/agents", discoveryAgentId, "discovery/events"],
    queryFn: async () => {
      const res = await fetch(`/api/mig/admin/agents/${discoveryAgentId}/discovery/events?limit=100`, { headers: TENANT_HEADERS });
      if (!res.ok) throw new Error("Failed to load discovery events");
      return res.json();
    },
    enabled: !!discoveryAgentId,
  });

  const startDiscoveryMutation = useMutation({
    mutationFn: async (agentId: string) => migPost(`/api/mig/admin/agents/${agentId}/discovery/start`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/agents"] });
      toast({ title: "Agent moved to discovery mode" });
    },
    onError: (e: Error) => toast({ title: "Failed to start discovery", description: e.message, variant: "destructive" }),
  });

  const generateDraftMutation = useMutation({
    mutationFn: async (agentId: string) => migPost(`/api/mig/admin/agents/${agentId}/discovery/generate-draft`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/drafts"] });
      queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/agents"] });
      toast({ title: "Draft intent profile generated" });
    },
    onError: (e: Error) => toast({ title: "Failed to generate draft", description: e.message, variant: "destructive" }),
  });

  const approveDraftMutation = useMutation({
    mutationFn: async (draftId: string) => migPost(`/api/mig/admin/drafts/${draftId}/approve`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/drafts"] });
      queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/agents"] });
      queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/intent-definitions"] });
      toast({ title: "Draft approved — agent locked to derived intent" });
    },
    onError: (e: Error) => toast({ title: "Approval failed", description: e.message, variant: "destructive" }),
  });

  const rejectDraftMutation = useMutation({
    mutationFn: async (draftId: string) => migPost(`/api/mig/admin/drafts/${draftId}/reject`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/drafts"] });
      queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/agents"] });
      toast({ title: "Draft rejected — agent returned to discovery" });
    },
    onError: (e: Error) => toast({ title: "Rejection failed", description: e.message, variant: "destructive" }),
  });

  const resolveDriftMutation = useMutation({
    mutationFn: async (eventId: string) => migPost(`/api/mig/admin/drift-events/${eventId}/resolve`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/drift-events"] });
      toast({ title: "Drift event resolved" });
    },
    onError: (e: Error) => toast({ title: "Resolve failed", description: e.message, variant: "destructive" }),
  });

  const requestMoreDiscoveryMutation = useMutation({
    mutationFn: async (agentId: string) => migPost(`/api/mig/admin/agents/${agentId}/discovery/request-more`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/agents"] });
      toast({ title: "Agent sent back to discovery for more observation" });
    },
    onError: (e: Error) => toast({ title: "Failed to request more discovery", description: e.message, variant: "destructive" }),
  });

  const setExceptionMutation = useMutation({
    mutationFn: async ({ agentId, granted }: { agentId: string; granted: boolean }) =>
      migPost(`/api/mig/admin/agents/${agentId}/discovery/exception`, { granted }),
    onSuccess: (_data, vars) => {
      queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/agents"] });
      toast({ title: vars.granted ? "Discovery exception granted" : "Discovery exception revoked" });
    },
    onError: (e: Error) => toast({ title: "Failed to update discovery exception", description: e.message, variant: "destructive" }),
  });

  const visibleDiscoveryAgents = filterByClientClass(
    (agentsQuery.data ?? []).filter((agent) => agent.lifecycleState === "discovery" || agent.lifecycleState === "reviewing"),
    discoveryClassFilter,
  );
  const visibleDrafts = filterByClientClass(draftsQuery.data ?? [], discoveryClassFilter);
  const visibleDriftEvents = filterByClientClass(driftEventsQuery.data ?? [], discoveryClassFilter);
  const visibleAuditEvents = filterByClientClass(auditQuery.data ?? [], auditClassFilter);
  const selectedDiscoveryAgent = agentsById.get(discoveryAgentId);
  useEffect(() => {
    if (discoveryAgentId && !visibleDiscoveryAgents.some((agent) => agent.agentId === discoveryAgentId)) {
      setDiscoveryAgentId("");
    }
  }, [discoveryAgentId, visibleDiscoveryAgents]);

  return (
    <div className="container mx-auto max-w-6xl p-6 space-y-6" data-testid="page-mig-admin">
      <div className="flex flex-col items-start justify-between gap-4 sm:flex-row sm:items-center">
        <div>
          <h1 className="text-2xl font-semibold flex items-center gap-2" data-testid="text-page-title">
            <ShieldCheck className="h-6 w-6" /> MIG — Intent Gateway {!simpleMig && <MigModeBadge plane={plane} loading={controlPlaneQuery.isLoading} />}
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            {simpleMig ? "Review tenant-visible clients and their restrictions, or discover a known endpoint or approved network target." : <>
            This is the <span className="font-medium text-foreground">agent identity + intent governance layer</span> — it controls <em>which declared intent</em> an agent is authorized to act under, and gates every tool call before it reaches the MCP server.
            For API key / credential management, use{" "}
            <button
              className="text-primary underline underline-offset-2 hover:no-underline inline-flex items-center gap-0.5"
              onClick={() => setLocation("/mcp-admin")}
              data-testid="link-go-to-mcp"
            >
              MCP Server — API Keys <ExternalLink className="h-3 w-3" />
            </button>.
            </>}
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-3">
          <Label htmlFor="simple-mig-toggle" className="text-sm font-medium">Simple MIG</Label>
          <Switch
            id="simple-mig-toggle"
            data-testid="toggle-simple-mig"
            checked={simpleMig}
            onCheckedChange={setSimpleMig}
            aria-label="Simple MIG"
          />
          {!simpleMig && <>
            {plane && <MigModeSetup plane={plane} />}
            <Button variant="outline" size="sm" onClick={() => seedMutation.mutate()} disabled={seedMutation.isPending} data-testid="button-seed-defaults">
              {seedMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <RefreshCw className="h-4 w-4 mr-2" />}
              Seed bripe-core-v1
            </Button>
          </>}
        </div>
      </div>

      {simpleMig ? <MigSimpleWorkspace /> : <>
      {controlPlaneQuery.isError && <div className="rounded-md border border-red-300 bg-red-50 p-3 text-sm text-red-800">MIG operating mode is unavailable. No healthy state is being assumed.</div>}
      {plane && (enterpriseMode ? <EnterpriseControlPlane plane={plane} /> : <FullControlSummary plane={plane} />)}

      <Tabs value={mainTab} onValueChange={setMainTab}>
        <TabsList className="h-auto flex-wrap justify-start">
          <TabsTrigger value="journeys" data-testid="tab-journeys"><GitBranch className="h-4 w-4 mr-1" /> Journeys</TabsTrigger>
          {enterpriseMode && <TabsTrigger value="control-plane" data-testid="tab-control-plane"><Server className="h-4 w-4 mr-1" /> Enterprise Control Plane</TabsTrigger>}
          {enterpriseMode && <TabsTrigger value="mcp-estate" data-testid="tab-mcp-estate"><Network className="h-4 w-4 mr-1" /> MCP Estate</TabsTrigger>}
          <TabsTrigger value="onboarding" data-testid="tab-onboarding"><UserPlus className="h-4 w-4 mr-1" /> Client Onboarding</TabsTrigger>
          <TabsTrigger value="agents" data-testid="tab-agents"><Key className="h-4 w-4 mr-1" /> Clients</TabsTrigger>
          <TabsTrigger value="libraries" data-testid="tab-libraries"><Boxes className="h-4 w-4 mr-1" /> Policies</TabsTrigger>
          {!enterpriseMode && <TabsTrigger value="discovery" data-testid="tab-discovery"><Radar className="h-4 w-4 mr-1" /> MCP Discovery</TabsTrigger>}
          <TabsTrigger value="audit" data-testid="tab-audit"><ScrollText className="h-4 w-4 mr-1" /> {enterpriseMode ? "Authority Sync" : "Registration Requests"}</TabsTrigger>
          <TabsTrigger value="host-operators" data-testid="tab-host-operators"><KeyRound className="h-4 w-4 mr-1" /> Host Operators</TabsTrigger>
          <TabsTrigger value="security" data-testid="tab-security"><ShieldQuestion className="h-4 w-4 mr-1" /> BRIPe Risk</TabsTrigger>
        </TabsList>

        <TabsContent value="journeys" className="space-y-6"><ObservationWorkspace /><div className="border-t pt-6"><h2 className="mb-3 text-base font-semibold">Governed journey history</h2><JourneysWorkspace /></div></TabsContent>
        <TabsContent value="control-plane" className="space-y-4">{plane && <EnterpriseControlPlane plane={plane} />}</TabsContent>
        <TabsContent value="mcp-estate" className="space-y-4">{plane && <McpEstate plane={plane} />}</TabsContent>
        <TabsContent value="host-operators" className="space-y-4"><MigHostOperators defaultOpen /></TabsContent>

        <TabsContent value="onboarding" className="space-y-4">
          <ClientOnboardingWorkspace />
        </TabsContent>

        <TabsContent value="agents" className="space-y-4">
          {enterpriseMode && <div className="rounded-md border bg-muted/30 p-3 text-sm text-muted-foreground" data-testid="enterprise-credential-note">MIG-native credentials are retained only for integrations, fallback, development, and approved special cases. Enterprise authority remains upstream.</div>}
          <div className="flex items-center justify-between gap-2">
            <Tabs value={clientClassFilter} onValueChange={(value) => setClientClassFilter(value as MigClientClassFilter)}>
              <TabsList>
                <TabsTrigger value="all" data-testid="filter-clients-all">All Clients</TabsTrigger>
                <TabsTrigger value="llm" data-testid="filter-clients-llm">LLM Clients</TabsTrigger>
                <TabsTrigger value="mcp" data-testid="filter-clients-mcp">MCP Clients</TabsTrigger>
              </TabsList>
            </Tabs>
            <div className="flex gap-2">
            <Button size="sm" onClick={() => setMainTab("onboarding")} data-testid="button-create-client">
              <Plus className="h-4 w-4 mr-1" /> Create Client
            </Button>
            <Dialog open={newAgentOpen} onOpenChange={setNewAgentOpen}>
              <DialogTrigger asChild>
                <Button size="sm" variant="outline" data-testid="button-new-agent"><Plus className="h-4 w-4 mr-1" /> Import Existing Client</Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader><DialogTitle>Import Existing MCP Client</DialogTitle></DialogHeader>
                <NewAgentForm
                  onSubmit={(body) => { createAgentMutation.mutate(body); setNewAgentOpen(false); }}
                  submitting={createAgentMutation.isPending}
                  defaultAgentId={keyIdParam || undefined}
                  mcpKeys={mcpKeysQuery.data}
                  linkedKeyIds={linkedKeyIds}
                />
              </DialogContent>
            </Dialog>
            </div>
          </div>

          {issuedAgentInfo && (
            <ConnectivityContractCard
              agentId={issuedAgentInfo.agentId}
              displayName={issuedAgentInfo.displayName}
              ticketSecret={issuedAgentInfo.ticketSecret}
              onDismiss={() => setIssuedAgentInfo(null)}
            />
          )}

          <Card>
            <CardHeader><CardTitle className="text-base">Registered Clients</CardTitle></CardHeader>
            <CardContent>
              {agentsQuery.isLoading ? (
                <Loader2 className="h-5 w-5 animate-spin" />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Agent ID</TableHead>
                      <TableHead>Name</TableHead>
                      <TableHead>Client Type</TableHead>
                      <TableHead>Trust</TableHead>
                      <TableHead>Risk Zones</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Lifecycle</TableHead>
                      <TableHead>MCP Keys</TableHead>
                      <TableHead>Intents</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {visibleAgents.map((a) => {
                      const isIntentsExpanded = expandedIntentsAgent === a.agentId;
                      const draftIntents = agentIntentDraft[a.agentId] ?? new Set<string>(a.allowedIntents ?? []);
                      const linkedKeys = getLinkedMcpKeys(a.agentId);
                      return (
                        <Fragment key={a.agentId}>
                          <TableRow data-testid={`row-agent-${a.agentId}`}>
                            <TableCell className="font-mono text-xs">{a.agentId}</TableCell>
                            <TableCell>
                              <div>{a.displayName}</div>
                            </TableCell>
                             <TableCell><ClientClassBadge agent={a} /></TableCell>
                            <TableCell>{a.trustLevel}</TableCell>
                            <TableCell>{(a.allowedRiskZones ?? []).join(", ")}</TableCell>
                            <TableCell><StatusBadge status={a.status} /></TableCell>
                            <TableCell><StatusBadge status={a.lifecycleState ?? "active"} /></TableCell>
                            <TableCell>
                              {linkedKeys.length === 0 ? (
                                <button
                                  className="text-[11px] text-muted-foreground underline underline-offset-1 hover:no-underline flex items-center gap-0.5"
                                  onClick={() => setLocation("/mcp-admin")}
                                  data-testid={`link-add-mcp-key-${a.agentId}`}
                                >
                                  <KeyRound className="h-2.5 w-2.5" /> Add key
                                </button>
                              ) : (
                                <div className="flex flex-col gap-0.5">
                                  {linkedKeys.map((k) => (
                                    <button
                                      key={k.id}
                                      className="text-[11px] text-primary underline underline-offset-1 hover:no-underline flex items-center gap-0.5"
                                      onClick={() => setLocation(`/mcp-admin?agentId=${encodeURIComponent(a.agentId)}`)}
                                      data-testid={`link-mcp-key-${k.id}-agent-${a.agentId}`}
                                      title={`Tenant: ${k.tenant_id} · ${k.classification}`}
                                    >
                                      <KeyRound className="h-2.5 w-2.5 shrink-0" />
                                      <span className="font-mono">{k.key_prefix}…</span>
                                      {k.status !== "active" && <span className="text-muted-foreground">({k.status})</span>}
                                    </button>
                                  ))}
                                </div>
                              )}
                            </TableCell>
                            <TableCell>
                              <Button
                                size="sm"
                                variant="outline"
                                className="gap-1 text-xs h-7 px-2"
                                data-testid={`button-toggle-intents-${a.agentId}`}
                                onClick={() => {
                                  if (isIntentsExpanded) {
                                    setExpandedIntentsAgent(null);
                                  } else {
                                    setExpandedIntentsAgent(a.agentId);
                                    if (!agentIntentDraft[a.agentId]) {
                                      setAgentIntentDraft(prev => ({
                                        ...prev,
                                        [a.agentId]: new Set<string>(a.allowedIntents ?? []),
                                      }));
                                    }
                                  }
                                }}
                              >
                                <ListChecks className="h-3 w-3" />
                                {(a.allowedIntents ?? []).length > 0 ? `${a.allowedIntents!.length} set` : "All"}
                                {isIntentsExpanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                              </Button>
                            </TableCell>
                            <TableCell>
                              <div className="flex gap-1 flex-wrap">
                                {a.status !== "active" && (
                                   <div className="flex flex-col items-center gap-1">
                                     <span className="text-[10px] font-medium text-muted-foreground">Activate</span>
                                     <Button size="sm" variant="outline" data-testid={`button-activate-${a.agentId}`}
                                       onClick={() => statusMutation.mutate({ agentId: a.agentId, status: "active" })}
                                       title="Activate agent"
                                       aria-label={`Activate ${a.displayName}`}>
                                       <CheckCircle2 className="h-3.5 w-3.5" />
                                     </Button>
                                   </div>
                                )}
                                {a.status !== "suspended" && (
                                   <div className="flex flex-col items-center gap-1">
                                     <span className="text-[10px] font-medium text-muted-foreground">Suspend</span>
                                     <Button size="sm" variant="outline" data-testid={`button-suspend-${a.agentId}`}
                                       onClick={() => statusMutation.mutate({ agentId: a.agentId, status: "suspended" })}
                                       title="Suspend agent"
                                       aria-label={`Suspend ${a.displayName}`}>
                                       <ShieldAlert className="h-3.5 w-3.5" />
                                     </Button>
                                   </div>
                                )}
                                {a.status !== "revoked" && (
                                   <div className="flex flex-col items-center gap-1">
                                     <span className="text-[10px] font-medium text-destructive">Delete</span>
                                     <Button size="sm" variant="destructive" data-testid={`button-revoke-${a.agentId}`}
                                       onClick={() => statusMutation.mutate({ agentId: a.agentId, status: "revoked" })}
                                       title="Delete agent"
                                       aria-label={`Delete ${a.displayName}`}>
                                       <ShieldOff className="h-3.5 w-3.5" />
                                     </Button>
                                   </div>
                                )}
                                {a.lifecycleState !== "discovery" && a.lifecycleState !== "locked" && (
                                  <Button size="sm" variant="outline" data-testid={`button-start-discovery-${a.agentId}`}
                                    onClick={() => startDiscoveryMutation.mutate(a.agentId)} title="Start discovery mode">
                                    <Radar className="h-3.5 w-3.5" />
                                  </Button>
                                )}
                                {(a.lifecycleState === "reviewing" || a.lifecycleState === "locked") && (
                                  <Button size="sm" variant="outline" data-testid={`button-request-more-discovery-${a.agentId}`}
                                    onClick={() => requestMoreDiscoveryMutation.mutate(a.agentId)} title="Send back to discovery for more observation">
                                    <FileSearch className="h-3.5 w-3.5" />
                                  </Button>
                                )}
                                {a.lifecycleState === "discovery" && (
                                  <Button size="sm" variant={a.discoveryExceptionGranted ? "default" : "outline"}
                                    data-testid={`button-toggle-exception-${a.agentId}`}
                                    onClick={() => setExceptionMutation.mutate({ agentId: a.agentId, granted: !a.discoveryExceptionGranted })}
                                    title={a.discoveryExceptionGranted ? "Revoke discovery sandbox exception" : "Grant discovery sandbox exception (allows high-risk/admin tools)"}>
                                    <AlertTriangle className="h-3.5 w-3.5" />
                                  </Button>
                                )}
                              </div>
                            </TableCell>
                          </TableRow>
                          {isIntentsExpanded && (
                            <TableRow key={`${a.agentId}-intents`} data-testid={`row-agent-intents-${a.agentId}`}>
                              <TableCell colSpan={10} className="bg-muted/30 px-6 py-4">
                                <div className="space-y-3">
                                  <div className="flex items-center gap-2">
                                    <ListChecks className="h-4 w-4 text-muted-foreground" />
                                    <span className="text-sm font-medium">Intent Permissions for "{a.displayName}"</span>
                                    <span className="text-xs text-muted-foreground">— check each intent this agent is allowed to act under</span>
                                  </div>
                                  {(() => {
                                    const allDefs = (intentsQuery.data ?? []).filter(i => i.status !== "deprecated");
                                    const primaryDefs = allDefs.filter(i => i.libraryId === "bripe-core-v1");
                                    const advancedDefs = allDefs.filter(i => i.libraryId !== "bripe-core-v1");
                                    const showAdvKey = `showAdv_${a.agentId}`;
                                    const showAdv = (expandedIntentsShowAdv ?? {})[showAdvKey] ?? false;
                                    const renderIntent = (intent: typeof allDefs[0]) => {
                                      const checked = draftIntents.has(intent.intentId);
                                      return (
                                        <div key={intent.intentId} className="flex items-start gap-3 p-2 rounded border bg-background">
                                          <Checkbox
                                            id={`agent-intent-${a.agentId}-${intent.intentId}`}
                                            checked={checked}
                                            onCheckedChange={(v) => {
                                              setAgentIntentDraft(prev => {
                                                const curr = new Set<string>(prev[a.agentId] ?? (a.allowedIntents ?? []));
                                                if (v) curr.add(intent.intentId); else curr.delete(intent.intentId);
                                                return { ...prev, [a.agentId]: curr };
                                              });
                                            }}
                                            data-testid={`checkbox-agent-intent-${a.agentId}-${intent.intentId}`}
                                            className="mt-0.5"
                                          />
                                          <Label
                                            htmlFor={`agent-intent-${a.agentId}-${intent.intentId}`}
                                            className="cursor-pointer flex-1 space-y-0.5"
                                          >
                                            <div className="font-medium text-sm text-foreground">{intent.name}</div>
                                            {intent.description && <div className="text-xs text-muted-foreground">{intent.description}</div>}
                                            <div className="text-xs text-muted-foreground font-mono">{intent.intentId}</div>
                                            {intent.riskZone && (
                                              <Badge variant="outline" className="text-[10px] px-1 py-0">{intent.riskZone}</Badge>
                                            )}
                                          </Label>
                                        </div>
                                      );
                                    };
                                    if (intentsQuery.isLoading) return <Loader2 className="h-4 w-4 animate-spin" />;
                                    if (allDefs.length === 0) return <p className="text-xs text-muted-foreground italic">No intent definitions found. Seed the bripe-core-v1 library first.</p>;
                                    return (
                                      <div className="space-y-2">
                                        <div className="grid grid-cols-1 gap-2 max-h-52 overflow-y-auto pr-2">
                                          {primaryDefs.map(renderIntent)}
                                          {primaryDefs.length === 0 && (
                                            <p className="text-xs text-muted-foreground italic">No BRIPe-native intents — seed bripe-core-v1 first.</p>
                                          )}
                                        </div>
                                        {advancedDefs.length > 0 && (
                                          <button
                                            type="button"
                                            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
                                            onClick={() => setExpandedIntentsShowAdv(prev => ({ ...prev, [showAdvKey]: !showAdv }))}
                                            data-testid={`button-toggle-adv-intents-${a.agentId}`}
                                          >
                                            {showAdv ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                                            {showAdv ? "Hide" : "Show"} other intents ({advancedDefs.length})
                                          </button>
                                        )}
                                        {showAdv && advancedDefs.length > 0 && (
                                          <div className="grid grid-cols-1 gap-2 max-h-40 overflow-y-auto pr-2 border-t pt-2">
                                            {advancedDefs.map(renderIntent)}
                                          </div>
                                        )}
                                      </div>
                                    );
                                  })()}
                                  <div className="flex items-center justify-between pt-1">
                                    <p className="text-xs text-muted-foreground">
                                      {draftIntents.size === 0
                                        ? "No restriction — all intents permitted (within risk zone ceiling)"
                                        : `${draftIntents.size} intent(s) approved`}
                                    </p>
                                    <div className="flex gap-2">
                                      <Button
                                        size="sm"
                                        variant="ghost"
                                        onClick={() => setExpandedIntentsAgent(null)}
                                        data-testid={`button-cancel-agent-intents-${a.agentId}`}
                                      >
                                        Cancel
                                      </Button>
                                      <Button
                                        size="sm"
                                        disabled={updateAgentIntentsMutation.isPending}
                                        onClick={() => updateAgentIntentsMutation.mutate({ agentId: a.agentId, intents: Array.from(draftIntents) })}
                                        data-testid={`button-save-agent-intents-${a.agentId}`}
                                      >
                                        {updateAgentIntentsMutation.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin mr-1" /> : <CheckCircle2 className="h-3.5 w-3.5 mr-1" />}
                                        Save Permissions
                                      </Button>
                                    </div>
                                  </div>
                                </div>
                              </TableCell>
                            </TableRow>
                          )}
                        </Fragment>
                      );
                    })}
                    {visibleAgents.length === 0 && (
                      <TableRow><TableCell colSpan={10} className="text-center text-muted-foreground py-6">No {clientClassFilter === "all" ? "" : clientClassFilter.toUpperCase() + " "}clients registered yet.</TableCell></TableRow>
                    )}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="libraries" className="space-y-4">
          <Card>
            <CardHeader><CardTitle className="text-base">Intent Libraries</CardTitle></CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Library ID</TableHead>
                    <TableHead>Name</TableHead>
                    <TableHead>Version</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(librariesQuery.data ?? []).map((l) => (
                    <TableRow key={l.libraryId} data-testid={`row-library-${l.libraryId}`}>
                      <TableCell className="font-mono text-xs">{l.libraryId}</TableCell>
                      <TableCell>{l.name}</TableCell>
                      <TableCell>{l.version}</TableCell>
                      <TableCell><StatusBadge status={l.status} /></TableCell>
                    </TableRow>
                  ))}
                  {(librariesQuery.data ?? []).length === 0 && (
                    <TableRow><TableCell colSpan={4} className="text-center text-muted-foreground py-6">No libraries yet — click "Seed bripe-core-v1".</TableCell></TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle className="text-base">Intent Definitions</CardTitle></CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Intent</TableHead>
                    <TableHead>Library</TableHead>
                    <TableHead>Risk Zone</TableHead>
                    <TableHead>State</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(intentsQuery.data ?? []).map((i) => (
                    <TableRow key={i.intentId} data-testid={`row-intent-${i.intentId}`}>
                      <TableCell>
                        <div className="font-medium text-sm text-foreground">{i.description || i.name}</div>
                        <div className="text-xs text-muted-foreground font-mono mt-0.5">{i.intentId}</div>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{i.libraryId}</TableCell>
                      <TableCell><Badge variant="outline">{i.riskZone}</Badge></TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          {i.status === "deprecated" ? (
                            <Badge variant="secondary" className="text-muted-foreground" data-testid={`badge-intent-state-${i.intentId}`}>disabled</Badge>
                          ) : (
                            <Badge variant="default" className="bg-emerald-600/90 hover:bg-emerald-600" data-testid={`badge-intent-state-${i.intentId}`}>enabled</Badge>
                          )}
                          <Button
                            size="sm"
                            variant="outline"
                            className="text-xs h-6 px-2"
                            data-testid={`button-toggle-intent-${i.intentId}`}
                            disabled={toggleIntentMutation.isPending}
                            onClick={() => toggleIntentMutation.mutate({ intentId: i.intentId, enable: i.status === "deprecated" })}
                          >
                            {i.status === "deprecated" ? "Enable" : "Disable"}
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                  {(intentsQuery.data ?? []).length === 0 && (
                    <TableRow><TableCell colSpan={4} className="text-center text-muted-foreground py-6">No intent definitions yet.</TableCell></TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="discovery" className="space-y-4">
          <div className="flex justify-end">
            <Select value={discoveryClassFilter} onValueChange={(value) => setDiscoveryClassFilter(value as MigClientClassFilter)}>
              <SelectTrigger className="w-52" data-testid="filter-discovery-client-type"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All client types</SelectItem>
                <SelectItem value="llm">LLM clients</SelectItem>
                <SelectItem value="mcp">MCP clients</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2"><Radar className="h-4 w-4" /> Agents in Discovery Mode</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground mb-3">
                These agents are currently unscoped and every discover/execute call they make is being captured. Use "Discovery Events by Agent" below to inspect what has been observed, then generate a draft profile.
              </p>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Agent ID</TableHead>
                    <TableHead>Name</TableHead>
                     <TableHead>Client Type</TableHead>
                    <TableHead>Lifecycle</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {visibleDiscoveryAgents.map((a) => (
                      <TableRow key={a.agentId} data-testid={`row-discovery-agent-${a.agentId}`}>
                        <TableCell className="font-mono text-xs">{a.agentId}</TableCell>
                        <TableCell>{a.displayName}</TableCell>
                        <TableCell><ClientClassBadge agent={a} /></TableCell>
                        <TableCell><StatusBadge status={a.lifecycleState} /></TableCell>
                        <TableCell><StatusBadge status={a.status} /></TableCell>
                      </TableRow>
                    ))}
                  {visibleDiscoveryAgents.length === 0 && (
                    <TableRow><TableCell colSpan={5} className="text-center text-muted-foreground py-6">No matching clients currently in discovery or under review.</TableCell></TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2"><FileSearch className="h-4 w-4" /> Draft Intent Profiles</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-xs text-muted-foreground">
                Agents in discovery mode capture every discover/execute call unscoped. Generate a draft profile from
                observed calls, then approve it to create a real intent definition and lock the agent to it.
              </p>
              {draftsQuery.isLoading ? (
                <Loader2 className="h-5 w-5 animate-spin" />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Draft ID</TableHead>
                      <TableHead>Agent</TableHead>
                      <TableHead>Client Type</TableHead>
                      <TableHead>Proposed Name</TableHead>
                      <TableHead>Tools</TableHead>
                      <TableHead>Risk Zone</TableHead>
                      <TableHead>Events</TableHead>
                      <TableHead>Confidence</TableHead>
                      <TableHead>Findings</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {visibleDrafts.map((d) => (
                      <TableRow key={d.draftId} data-testid={`row-draft-${d.draftId}`}>
                        <TableCell className="font-mono text-xs">{d.draftId}</TableCell>
                        <TableCell className="font-mono text-xs">{d.agentId}</TableCell>
                        <TableCell><ClientClassBadge agent={agentsById.get(d.agentId)} /></TableCell>
                        <TableCell>
                          <div className="font-medium">{d.proposedName}</div>
                          <div className="text-xs text-muted-foreground max-w-xs truncate">{d.proposedDescription}</div>
                        </TableCell>
                        <TableCell className="text-xs max-w-[16rem] truncate" title={(d.proposedAllowedToolNames ?? []).join(", ")}>
                          {(d.proposedAllowedToolNames ?? []).join(", ") || "—"}
                        </TableCell>
                        <TableCell><Badge variant="outline">{d.proposedRiskZone}</Badge></TableCell>
                        <TableCell>{d.observedEventCount}</TableCell>
                        <TableCell data-testid={`text-confidence-${d.draftId}`}>{d.confidence}%</TableCell>
                        <TableCell className="text-xs max-w-[12rem] truncate" title={d.evidenceSummary}>
                          {(d.policyFindings ?? []).length > 0 ? (
                            <span className="text-yellow-600 dark:text-yellow-400">{(d.policyFindings ?? []).length} denied attempt(s)</span>
                          ) : (
                            <span className="text-muted-foreground">none</span>
                          )}
                        </TableCell>
                        <TableCell><StatusBadge status={d.status} /></TableCell>
                        <TableCell className="flex gap-1">
                          {d.status === "pending" && (
                            <>
                              <Button size="sm" variant="outline" data-testid={`button-approve-draft-${d.draftId}`}
                                onClick={() => approveDraftMutation.mutate(d.draftId)} disabled={approveDraftMutation.isPending}>
                                <CheckCircle2 className="h-3.5 w-3.5" />
                              </Button>
                              <Button size="sm" variant="destructive" data-testid={`button-reject-draft-${d.draftId}`}
                                onClick={() => rejectDraftMutation.mutate(d.draftId)} disabled={rejectDraftMutation.isPending}>
                                <XCircle className="h-3.5 w-3.5" />
                              </Button>
                            </>
                          )}
                          {d.status === "approved" && d.resultingIntentId && (
                            <span className="text-xs font-mono text-muted-foreground">{d.resultingIntentId}</span>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                    {visibleDrafts.length === 0 && (
                      <TableRow><TableCell colSpan={11} className="text-center text-muted-foreground py-6">No draft profiles yet.</TableCell></TableRow>
                    )}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2"><Lock className="h-4 w-4" /> Locked Profiles</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground mb-3">
                Agents whose approved draft was locked into a real intent — from this point on, discovery/execution only ever returns tools within that approved scope; anything else is denied and, for locked/active agents, recorded as a drift event.
              </p>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Agent ID</TableHead>
                    <TableHead>Name</TableHead>
                    <TableHead>Client Type</TableHead>
                    <TableHead>Approved Intent</TableHead>
                    <TableHead>Approved Tools</TableHead>
                    <TableHead>Lifecycle</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {visibleDrafts
                    .filter((d) => d.status === "approved" && d.resultingIntentId)
                    .map((d) => {
                      const agent = (agentsQuery.data ?? []).find((a) => a.agentId === d.agentId);
                      return (
                        <TableRow key={d.draftId} data-testid={`row-locked-${d.draftId}`}>
                          <TableCell className="font-mono text-xs">{d.agentId}</TableCell>
                          <TableCell>{agent?.displayName ?? "—"}</TableCell>
                          <TableCell><ClientClassBadge agent={agent} /></TableCell>
                          <TableCell className="font-mono text-xs">{d.resultingIntentId}</TableCell>
                          <TableCell className="text-xs max-w-[16rem] truncate" title={(d.proposedAllowedToolNames ?? []).join(", ")}>
                            {(d.proposedAllowedToolNames ?? []).join(", ") || "—"}
                          </TableCell>
                          <TableCell><StatusBadge status={agent?.lifecycleState ?? "locked"} /></TableCell>
                        </TableRow>
                      );
                    })}
                  {visibleDrafts.filter((d) => d.status === "approved" && d.resultingIntentId).length === 0 && (
                    <TableRow><TableCell colSpan={6} className="text-center text-muted-foreground py-6">No locked profiles yet.</TableCell></TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2"><Radar className="h-4 w-4" /> Discovery Events by Agent</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex items-center gap-2 max-w-xl">
                <Select value={discoveryAgentId} onValueChange={setDiscoveryAgentId}>
                  <SelectTrigger className="min-w-72" data-testid="select-discovery-client">
                    <SelectValue placeholder={`Select ${discoveryClassFilter === "all" ? "" : discoveryClassFilter.toUpperCase() + " "}client`} />
                  </SelectTrigger>
                  <SelectContent>
                    {visibleDiscoveryAgents.map((agent) => (
                      <SelectItem key={agent.agentId} value={agent.agentId}>
                        {agent.displayName} · {migClientClass(agent).toUpperCase()}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {selectedDiscoveryAgent && <ClientClassBadge agent={selectedDiscoveryAgent} />}
                <Button
                  size="sm"
                  variant="outline"
                  data-testid="button-generate-draft"
                  disabled={!discoveryAgentId || generateDraftMutation.isPending}
                  onClick={() => generateDraftMutation.mutate(discoveryAgentId)}
                >
                  {generateDraftMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
                  Generate Draft
                </Button>
              </div>
              {discoveryAgentId && (
                discoveryEventsQuery.isLoading ? (
                  <Loader2 className="h-5 w-5 animate-spin" />
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Time</TableHead>
                        <TableHead>Kind</TableHead>
                        <TableHead>Tool</TableHead>
                        <TableHead>Capability</TableHead>
                        <TableHead>Domain Hints</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {(discoveryEventsQuery.data ?? []).map((ev) => (
                        <TableRow key={ev.eventId} data-testid={`row-discovery-event-${ev.eventId}`}>
                          <TableCell className="text-xs">{new Date(ev.createdAt).toLocaleString()}</TableCell>
                          <TableCell><Badge variant="outline">{ev.requestKind}</Badge></TableCell>
                          <TableCell className="font-mono text-xs">{ev.toolName ?? "—"}</TableCell>
                          <TableCell className="font-mono text-xs">{ev.capabilityId ?? "—"}</TableCell>
                          <TableCell className="text-xs">{(ev.domainHints ?? []).join(", ") || "—"}</TableCell>
                        </TableRow>
                      ))}
                      {(discoveryEventsQuery.data ?? []).length === 0 && (
                        <TableRow><TableCell colSpan={5} className="text-center text-muted-foreground py-6">No discovery events captured yet for this agent.</TableCell></TableRow>
                      )}
                    </TableBody>
                  </Table>
                )
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2"><GitBranch className="h-4 w-4" /> Drift Events</CardTitle>
            </CardHeader>
            <CardContent>
              {driftEventsQuery.isLoading ? (
                <Loader2 className="h-5 w-5 animate-spin" />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Time</TableHead>
                      <TableHead>Agent</TableHead>
                      <TableHead>Client Type</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Tool</TableHead>
                      <TableHead>Detail</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {visibleDriftEvents.map((ev) => (
                      <TableRow key={ev.eventId} data-testid={`row-drift-${ev.eventId}`}>
                        <TableCell className="text-xs">{new Date(ev.createdAt).toLocaleString()}</TableCell>
                        <TableCell className="font-mono text-xs">{ev.agentId}</TableCell>
                        <TableCell><ClientClassBadge agent={agentsById.get(ev.agentId)} /></TableCell>
                        <TableCell>{ev.driftType}</TableCell>
                        <TableCell className="font-mono text-xs">{ev.toolName ?? "—"}</TableCell>
                        <TableCell className="text-xs max-w-xs truncate" title={ev.detail}>{ev.detail}</TableCell>
                        <TableCell><StatusBadge status={ev.severity} /></TableCell>
                        <TableCell>{ev.resolved ? <Badge variant="outline">resolved</Badge> : <Badge className="bg-orange-500/15 text-orange-600 dark:text-orange-400">open</Badge>}</TableCell>
                        <TableCell>
                          {!ev.resolved && (
                            <Button size="sm" variant="outline" data-testid={`button-resolve-drift-${ev.eventId}`}
                              onClick={() => resolveDriftMutation.mutate(ev.eventId)} disabled={resolveDriftMutation.isPending}>
                              <CheckCircle2 className="h-3.5 w-3.5" />
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                    {visibleDriftEvents.length === 0 && (
                      <TableRow><TableCell colSpan={9} className="text-center text-muted-foreground py-6">No drift events recorded.</TableCell></TableRow>
                    )}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="audit">
          <Card>
            <CardHeader className="flex-row items-center justify-between">
              <CardTitle className="text-base">Gateway Decisions</CardTitle>
              <Select value={auditClassFilter} onValueChange={(value) => setAuditClassFilter(value as MigClientClassFilter)}>
                <SelectTrigger className="w-52" data-testid="filter-audit-client-type"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All client types</SelectItem>
                  <SelectItem value="llm">LLM clients</SelectItem>
                  <SelectItem value="mcp">MCP clients</SelectItem>
                </SelectContent>
              </Select>
            </CardHeader>
            <CardContent>
              {auditQuery.isLoading ? (
                <Loader2 className="h-5 w-5 animate-spin" />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Time</TableHead>
                      <TableHead>Agent</TableHead>
                       <TableHead>Client Type</TableHead>
                      <TableHead>Intent</TableHead>
                      <TableHead>Event</TableHead>
                      <TableHead>Decision</TableHead>
                      <TableHead>Reason / Proof</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {visibleAuditEvents.map((e) => (
                      <TableRow key={e.id} data-testid={`row-audit-${e.id}`}>
                        <TableCell className="text-xs">{new Date(e.createdAt).toLocaleString()}</TableCell>
                        <TableCell className="font-mono text-xs">{e.agentId}</TableCell>
                        <TableCell><ClientClassBadge agent={agentsById.get(e.agentId)} /></TableCell>
                        <TableCell className="font-mono text-xs">{e.intentId ?? "—"}</TableCell>
                        <TableCell>{e.eventType}</TableCell>
                        <TableCell><StatusBadge status={e.decision} /></TableCell>
                        <TableCell className="text-xs max-w-xs truncate" title={e.reason ?? e.transitionProofId}>
                          {e.reason ?? e.transitionProofId ?? "—"}
                        </TableCell>
                      </TableRow>
                    ))}
                    {visibleAuditEvents.length === 0 && (
                      <TableRow><TableCell colSpan={7} className="text-center text-muted-foreground py-6">No gateway activity for this client type.</TableCell></TableRow>
                    )}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="security" className="space-y-4">
          <MS5SecurityPanel />
        </TabsContent>

      </Tabs>
      </>}
    </div>
  );
}

// ─── MS5 Security Panel ───────────────────────────────────────────────────────

function gradeColor(grade: string): string {
  if (grade === "A+" || grade === "A") return "text-green-600 dark:text-green-400";
  if (grade === "B") return "text-blue-600 dark:text-blue-400";
  if (grade === "C") return "text-yellow-600 dark:text-yellow-400";
  if (grade === "D") return "text-orange-600 dark:text-orange-400";
  return "text-red-600 dark:text-red-400";
}

function SeverityBadgeMs5({ severity }: { severity: string }) {
  const cls: Record<string, string> = {
    critical: "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300 border border-red-200 dark:border-red-700",
    high: "bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-300 border border-orange-200 dark:border-orange-700",
    medium: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300 border border-yellow-200 dark:border-yellow-700",
    low: "bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300 border border-blue-200 dark:border-blue-700",
    info: "bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300 border border-gray-200 dark:border-gray-700",
  };
  return <span className={`px-2 py-0.5 rounded text-xs font-semibold ${cls[severity] ?? "bg-gray-100 text-gray-700"}`}>{severity.toUpperCase()}</span>;
}

const LAYER_LABELS: Record<string, string> = {
  layer1: "L1 — Capability Correctness",
  layer2: "L2 — Capability Assurance",
  layer3: "L3 — Intent Governance",
  layer4: "L4 — Decision Integrity",
  layer5: "L5 — Operational Governance",
};

function TrendSparkline({ history }: { history: Array<{ overall_score: number }> }) {
  if (history.length < 2) return null;
  const scores = history.map(h => h.overall_score);
  const max = Math.max(...scores, 1);
  const w = 120, h = 28, pad = 2;
  const pts = scores.map((s, i) => {
    const x = pad + (i / (scores.length - 1)) * (w - pad * 2);
    const y = pad + (1 - s / max) * (h - pad * 2);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
  const last = scores[scores.length - 1];
  const prev = scores[scores.length - 2];
  const color = last >= prev ? "#22c55e" : "#ef4444";
  return (
    <div className="flex items-center gap-2 text-xs text-muted-foreground" data-testid="chart-ms5-trend-sparkline">
      <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} className="overflow-visible">
        <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" />
        {scores.map((s, i) => {
          const x = pad + (i / (scores.length - 1)) * (w - pad * 2);
          const y = pad + (1 - s / max) * (h - pad * 2);
          return <circle key={i} cx={x} cy={y} r="2" fill={color} />;
        })}
      </svg>
      <span style={{ color }}>{last >= prev ? "▲" : "▼"} {last}/100</span>
    </div>
  );
}

function CertificationBadge({ state }: { state: MS5CertificationState | null | undefined }) {
  if (!state) return null;
  const cfg: Record<MS5CertificationState, { label: string; cls: string; icon: React.ReactNode }> = {
    CERTIFIED: { label: "CERTIFIED", cls: "bg-green-500/15 text-green-700 dark:text-green-400 border border-green-300 dark:border-green-700", icon: <Award className="h-3.5 w-3.5" /> },
    CERTIFIED_WITH_WARNINGS: { label: "CERTIFIED w/ WARNINGS", cls: "bg-yellow-500/15 text-yellow-700 dark:text-yellow-400 border border-yellow-300 dark:border-yellow-700", icon: <ShieldAlert className="h-3.5 w-3.5" /> },
    CONDITIONAL: { label: "CONDITIONAL", cls: "bg-orange-500/15 text-orange-700 dark:text-orange-400 border border-orange-300 dark:border-orange-700", icon: <AlertTriangle className="h-3.5 w-3.5" /> },
    FAILED: { label: "FAILED", cls: "bg-red-500/15 text-red-700 dark:text-red-400 border border-red-300 dark:border-red-700", icon: <ShieldOff className="h-3.5 w-3.5" /> },
    BLOCKED: { label: "BLOCKED", cls: "bg-red-900/20 text-red-800 dark:text-red-300 border border-red-500 dark:border-red-600 font-black", icon: <Lock className="h-3.5 w-3.5" /> },
  };
  const c = cfg[state];
  if (!c) return null;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold ${c.cls}`} data-testid="badge-ms5-certification-state">
      {c.icon}{c.label}
    </span>
  );
}

function EscapeRouteGraph({ analysis }: { analysis: any }) {
  if (!analysis) return <div className="text-xs text-muted-foreground py-4 text-center">No escape route analysis available. Run a review first.</div>;

  const nodes: any[] = analysis.nodes ?? [];
  const edges: any[] = analysis.edges ?? [];
  const paths: any[] = analysis.canonical_paths ?? [];

  const nodeById = new Map(nodes.map((n: any) => [n.id, n]));
  const SVG_W = 640, SVG_H = 320;

  const classColor = (ms5Class: string) => {
    if (ms5Class === "ADMIN" || ms5Class === "DANGEROUS") return "#ef4444";
    if (ms5Class === "EXECUTION") return "#f59e0b";
    return "#3b82f6";
  };

  return (
    <div className="space-y-3" data-testid="card-escape-route-graph">
      <div className="flex items-center gap-3 text-xs text-muted-foreground flex-wrap">
        <span className="flex items-center gap-1"><span className="inline-block w-3 h-3 rounded-full bg-blue-500" />read_only</span>
        <span className="flex items-center gap-1"><span className="inline-block w-3 h-3 rounded-full bg-amber-500" />execution</span>
        <span className="flex items-center gap-1"><span className="inline-block w-3 h-3 rounded-full bg-red-500" />admin / dangerous</span>
        <span className="ml-auto text-muted-foreground">{analysis.total_paths_discovered} paths discovered — highest-risk terminus: <strong className="text-foreground">{analysis.highest_risk_terminus}</strong></span>
      </div>
      <div className="border rounded overflow-auto bg-muted/20">
        <svg viewBox={`0 0 ${SVG_W} ${SVG_H}`} width="100%" height={SVG_H} className="block">
          <defs>
            <marker id="arrowhead" markerWidth="6" markerHeight="4" refX="6" refY="2" orient="auto">
              <polygon points="0 0, 6 2, 0 4" fill="#888" />
            </marker>
          </defs>
          {edges.slice(0, 30).map((e: any, i: number) => {
            const from = nodeById.get(e.from);
            const to = nodeById.get(e.to);
            if (!from?.x || !to?.x) return null;
            const risk = e.risk_weight ?? 0;
            const strokeColor = risk >= 0.7 ? "#ef4444" : risk >= 0.4 ? "#f59e0b" : "#6b7280";
            return (
              <g key={i}>
                <line
                  x1={from.x} y1={from.y}
                  x2={to.x} y2={to.y}
                  stroke={strokeColor} strokeWidth={risk >= 0.7 ? 2 : 1}
                  strokeOpacity={0.6}
                  markerEnd="url(#arrowhead)"
                />
              </g>
            );
          })}
          {nodes.slice(0, 40).map((n: any) => (
            <g key={n.id} transform={`translate(${n.x ?? 0},${n.y ?? 0})`}>
              <circle r={6} fill={classColor(n.ms5_class ?? "")} opacity={0.85} />
              <title>{n.capability_name} ({n.ms5_class})</title>
            </g>
          ))}
        </svg>
      </div>

      {paths.length > 0 && (
        <div className="space-y-2">
          <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Canonical Escape Paths</div>
          {paths.map((p: any) => (
            <div key={p.path_id} className="border rounded p-2 bg-muted/30 text-xs space-y-1" data-testid={`card-escape-path-${p.path_type}`}>
              <div className="flex items-center gap-2">
                <span className={`font-semibold uppercase ${p.path_type === "highest_risk" ? "text-red-600 dark:text-red-400" : p.path_type === "most_likely" ? "text-orange-600 dark:text-orange-400" : "text-blue-600 dark:text-blue-400"}`}>
                  {p.path_type.replace(/_/g, " ")}
                </span>
                <span className="text-muted-foreground">→ terminus: <strong className="text-foreground">{p.terminates_at}</strong></span>
                <span className="ml-auto text-muted-foreground">risk: <strong className="text-foreground">{p.cumulative_risk_score}</strong></span>
              </div>
              <div className="flex items-center gap-1 flex-wrap">
                {(p.nodes ?? []).map((nodeId: string, i: number) => {
                  const n = nodeById.get(nodeId);
                  const name = n?.capability_name ?? nodeId.replace("node_", "");
                  return (
                    <Fragment key={nodeId}>
                      <span className={`px-1.5 py-0.5 rounded font-mono ${
                        n?.ms5_class === "ADMIN" || n?.ms5_class === "DANGEROUS" ? "bg-red-500/15 text-red-600 dark:text-red-400" :
                        n?.ms5_class === "EXECUTION" ? "bg-amber-500/15 text-amber-600 dark:text-amber-400" :
                        "bg-blue-500/15 text-blue-600 dark:text-blue-400"
                      }`}>{name}</span>
                      {i < (p.nodes ?? []).length - 1 && <ArrowRight className="h-3 w-3 text-muted-foreground shrink-0" />}
                    </Fragment>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function IntentValidationPanel({ validation }: { validation: any }) {
  if (!validation) return <div className="text-xs text-muted-foreground py-4 text-center">No intent validation available. Run a review first.</div>;

  const products: any[] = validation.validations ?? [];
  return (
    <div className="space-y-3" data-testid="card-intent-validation">
      <div className="flex gap-4 text-xs text-muted-foreground flex-wrap">
        <span>Products validated: <strong className="text-foreground">{validation.products_validated}</strong></span>
        <span>Total violations: <strong className={validation.total_violations > 0 ? "text-orange-600 dark:text-orange-400" : "text-green-600 dark:text-green-400"}>{validation.total_violations}</strong></span>
        <span>Critical violations: <strong className={validation.critical_violations > 0 ? "text-red-600 dark:text-red-400" : "text-green-600 dark:text-green-400"}>{validation.critical_violations}</strong></span>
      </div>
      <div className="space-y-2">
        {products.map((prod: any) => (
          <div key={prod.product_id} className={`border rounded p-3 ${prod.validation_passed ? "border-green-300 dark:border-green-800 bg-green-500/5" : "border-orange-300 dark:border-orange-800 bg-orange-500/5"}`} data-testid={`card-intent-product-${prod.product_id}`}>
            <div className="flex items-center gap-2 mb-1">
              {prod.validation_passed
                ? <CheckCircle2 className="h-4 w-4 text-green-600 dark:text-green-400 shrink-0" />
                : <AlertTriangle className="h-4 w-4 text-orange-600 dark:text-orange-400 shrink-0" />}
              <span className="text-sm font-semibold">{prod.product_name}</span>
              <span className="text-xs text-muted-foreground ml-auto">{prod.visible_capabilities?.length ?? 0} capabilities visible</span>
            </div>
            <div className="text-xs text-muted-foreground">{prod.declared_intent}</div>
            {prod.violations?.length > 0 && (
              <div className="mt-2 space-y-1">
                {prod.violations.map((v: any, i: number) => (
                  <div key={i} className="flex items-start gap-2 text-xs">
                    <SeverityBadgeMs5 severity={v.severity} />
                    <span className="font-mono text-muted-foreground">{v.capability_name}</span>
                    <span className="text-foreground">{v.evidence}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function AutomatedTestsPanel({ tests }: { tests: any[] }) {
  const [filterType, setFilterType] = useState<string>("");
  const [filterCap, setFilterCap] = useState<string>("");

  const filtered = tests.filter(t =>
    (!filterType || t.testType === filterType) &&
    (!filterCap || t.capabilityName?.includes(filterCap))
  );

  const typeCounts = tests.reduce((acc: Record<string, number>, t: any) => {
    acc[t.testType] = (acc[t.testType] ?? 0) + 1;
    return acc;
  }, {});

  const testTypes = Object.keys(typeCounts);

  const passCount = tests.filter(t => t.lastPass === true).length;
  const failCount = tests.filter(t => t.lastPass === false).length;

  return (
    <div className="space-y-3" data-testid="panel-automated-tests">
      <div className="flex gap-4 text-xs text-muted-foreground flex-wrap">
        <span>Total: <strong className="text-foreground">{tests.length}</strong></span>
        <span>Passed: <strong className="text-green-600 dark:text-green-400">{passCount}</strong></span>
        <span>Failed: <strong className="text-red-600 dark:text-red-400">{failCount}</strong></span>
        <span>Untested: <strong className="text-muted-foreground">{tests.length - passCount - failCount}</strong></span>
      </div>
      <div className="flex flex-wrap gap-2 text-xs">
        {testTypes.map(type => (
          <button key={type}
            onClick={() => setFilterType(filterType === type ? "" : type)}
            className={`px-2 py-0.5 rounded border text-xs transition-colors ${filterType === type ? "border-primary bg-primary/10 text-primary" : "border-border hover:bg-muted/50"}`}
            data-testid={`button-test-filter-${type}`}
          >
            {type} ({typeCounts[type]})
          </button>
        ))}
      </div>
      <div className="flex gap-2 items-center">
        <input
          className="text-xs border rounded px-2 py-1 bg-background w-48"
          placeholder="Filter by capability…"
          value={filterCap}
          onChange={e => setFilterCap(e.target.value)}
          data-testid="input-test-capability-filter"
        />
        {(filterType || filterCap) && (
          <button className="text-xs text-muted-foreground underline" onClick={() => { setFilterType(""); setFilterCap(""); }}>Clear</button>
        )}
      </div>
      {filtered.length === 0 ? (
        <div className="text-center text-muted-foreground text-sm py-6">
          <TestTube2 className="h-8 w-8 mx-auto mb-2 opacity-30" />
          {tests.length === 0 ? "No tests generated yet. Run a Review to auto-generate tests." : "No tests match the current filter."}
        </div>
      ) : (
        <div className="overflow-x-auto border rounded">
          <Table data-testid="table-generated-tests">
            <TableHeader>
              <TableRow>
                <TableHead className="text-xs">Capability</TableHead>
                <TableHead className="text-xs">Type</TableHead>
                <TableHead className="text-xs">Test Name</TableHead>
                <TableHead className="text-xs">Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.slice(0, 80).map((t: any, i: number) => (
                <TableRow key={t.id ?? i} data-testid={`row-test-${t.id ?? i}`}>
                  <TableCell className="text-xs font-mono py-1 max-w-[120px] truncate">{t.capabilityName}</TableCell>
                  <TableCell className="text-xs py-1">
                    <span className="px-1.5 py-0.5 rounded bg-primary/10 text-primary text-xs">{t.testType}</span>
                  </TableCell>
                  <TableCell className="text-xs py-1 max-w-[240px] truncate">{t.testName}</TableCell>
                  <TableCell className="text-xs py-1">
                    {t.lastPass === true && <span className="text-green-600 dark:text-green-400">✓ Pass</span>}
                    {t.lastPass === false && <span className="text-red-600 dark:text-red-400">✗ Fail</span>}
                    {t.lastPass == null && <span className="text-muted-foreground">—</span>}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          {filtered.length > 80 && <div className="text-xs text-muted-foreground text-center py-2">Showing 80 of {filtered.length} tests</div>}
        </div>
      )}
    </div>
  );
}

function PatchQueuePanel({ patches, onApprove, onReject, onQueue, onMerge, isActing }: {
  patches: any[];
  onApprove: (id: number) => void;
  onReject: (id: number) => void;
  onQueue: (id: number) => void;
  onMerge: (id: number) => void;
  isActing: boolean;
}) {
  const [statusFilter, setStatusFilter] = useState<string>("");
  const filtered = patches.filter(p => !statusFilter || p.status === statusFilter);
  const statuses = ["PENDING", "APPROVED", "QUEUED", "MERGED", "REJECTED"];

  const statusCls: Record<string, string> = {
    PENDING: "bg-yellow-500/15 text-yellow-700 dark:text-yellow-400",
    APPROVED: "bg-green-500/15 text-green-700 dark:text-green-400",
    QUEUED: "bg-blue-500/15 text-blue-700 dark:text-blue-400",
    MERGED: "bg-purple-500/15 text-purple-700 dark:text-purple-400",
    REJECTED: "bg-red-500/15 text-red-700 dark:text-red-400",
  };

  const regressionCls: Record<string, string> = {
    low: "text-green-600 dark:text-green-400",
    medium: "text-yellow-600 dark:text-yellow-400",
    high: "text-red-600 dark:text-red-400",
  };

  return (
    <div className="space-y-3" data-testid="panel-patch-queue">
      <div className="flex gap-2 flex-wrap">
        {statuses.map(s => {
          const count = patches.filter(p => p.status === s).length;
          return (
            <button key={s}
              onClick={() => setStatusFilter(statusFilter === s ? "" : s)}
              className={`px-2 py-0.5 rounded border text-xs transition-colors ${statusFilter === s ? "border-primary bg-primary/10 text-primary" : "border-border hover:bg-muted/50"}`}
              data-testid={`button-patch-filter-${s.toLowerCase()}`}
            >
              {s} ({count})
            </button>
          );
        })}
      </div>
      {filtered.length === 0 ? (
        <div className="text-center text-muted-foreground text-sm py-6">
          <GitMerge className="h-8 w-8 mx-auto mb-2 opacity-30" />
          {patches.length === 0 ? "No patches generated yet. Run a Review to auto-generate patches for high/critical findings." : "No patches match the current filter."}
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((patch: any) => (
            <div key={patch.id} className="border rounded p-3 space-y-2 hover:bg-muted/30 transition-colors" data-testid={`card-patch-${patch.id}`}>
              <div className="flex items-start gap-2 flex-wrap">
                <span className={`px-2 py-0.5 rounded text-xs font-semibold ${statusCls[patch.status] ?? "bg-muted text-muted-foreground"}`}>{patch.status}</span>
                {patch.capabilityName && <span className="text-xs font-mono text-muted-foreground">{patch.capabilityName}</span>}
                <span className="text-xs text-muted-foreground flex-1 truncate">{patch.findingSummary}</span>
              </div>
              <div className="flex flex-wrap gap-4 text-xs text-muted-foreground">
                <span>Risk: <strong className="text-foreground">{patch.riskBefore} → {patch.riskAfter}</strong></span>
                <span>Coverage Δ: <strong className="text-foreground">+{patch.coverageDelta}%</strong></span>
                <span>Regression: <strong className={regressionCls[patch.regressionRisk] ?? "text-foreground"}>{patch.regressionRisk}</strong></span>
              </div>
              {patch.impactDescription && (
                <div className="text-xs text-muted-foreground bg-muted/50 rounded p-2">{patch.impactDescription.slice(0, 150)}{patch.impactDescription.length > 150 ? "…" : ""}</div>
              )}
              {patch.diffText && (
                <details className="text-xs">
                  <summary className="cursor-pointer text-muted-foreground hover:text-foreground">View diff</summary>
                  <pre className="mt-1 p-2 bg-muted rounded overflow-x-auto text-xs font-mono whitespace-pre-wrap text-muted-foreground">{patch.diffText.slice(0, 800)}</pre>
                </details>
              )}
              {(patch.status === "PENDING" || patch.status === "APPROVED" || patch.status === "QUEUED") && (
                <div className="flex gap-2 flex-wrap">
                  {patch.status === "PENDING" && (
                    <>
                      <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => onApprove(patch.id)} disabled={isActing} data-testid={`button-approve-patch-${patch.id}`}>
                        <CheckCircle2 className="h-3 w-3 mr-1" /> Approve
                      </Button>
                      <Button size="sm" variant="outline" className="h-7 text-xs text-red-600 dark:text-red-400 hover:bg-red-500/10" onClick={() => onReject(patch.id)} disabled={isActing} data-testid={`button-reject-patch-${patch.id}`}>
                        <XCircle className="h-3 w-3 mr-1" /> Reject
                      </Button>
                    </>
                  )}
                  {patch.status === "APPROVED" && (
                    <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => onQueue(patch.id)} disabled={isActing} data-testid={`button-queue-patch-${patch.id}`}>
                      <GitPullRequest className="h-3 w-3 mr-1" /> Queue for Merge
                    </Button>
                  )}
                  {patch.status === "QUEUED" && (
                    <Button size="sm" className="h-7 text-xs bg-purple-600 hover:bg-purple-700 text-white" onClick={() => onMerge(patch.id)} disabled={isActing} data-testid={`button-merge-patch-${patch.id}`}>
                      {isActing ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : <GitMerge className="h-3 w-3 mr-1" />}
                      Merge & Validate
                    </Button>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function MS5SecurityPanel() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [layerFilter, setLayerFilter] = useState<string>("");
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [showInventory, setShowInventory] = useState(false);
  const [acknowledgingId, setAcknowledgingId] = useState<string | null>(null);
  const [ms5SubTab, setMs5SubTab] = useState<string>("scorecard");
  const [actingPatchId, setActingPatchId] = useState<number | null>(null);

  const MS5_HEADERS = { "Content-Type": "application/json", "x-tenant-id": "default" };

  const reportQuery = useQuery<{ ok: boolean; report: MS5Report | null }>({
    queryKey: ["/api/mig/security/report"],
    queryFn: () => fetch("/api/mig/security/report", { headers: MS5_HEADERS }).then(r => r.json()),
    refetchOnWindowFocus: false,
  });

  const historyQuery = useQuery<{ ok: boolean; history: Array<{ report_id: string; overall_score: number; grade: string; generated_at: string }> }>({
    queryKey: ["/api/mig/security/history"],
    queryFn: () => fetch("/api/mig/security/history", { headers: MS5_HEADERS }).then(r => r.json()),
    refetchOnWindowFocus: false,
  });

  const findingsQuery = useQuery<{ ok: boolean; findings: MS5Finding[] }>({
    queryKey: ["/api/mig/security/findings", severityFilter, layerFilter],
    queryFn: () => {
      const params = new URLSearchParams({ acknowledged: "false" });
      if (severityFilter) params.set("severity", severityFilter);
      if (layerFilter) params.set("layer", layerFilter);
      return fetch(`/api/mig/security/findings?${params}`, { headers: MS5_HEADERS }).then(r => r.json());
    },
    refetchOnWindowFocus: false,
  });

  const escapeRouteQuery = useQuery<{ ok: boolean; escape_route_analysis: any }>({
    queryKey: ["/api/mig/security/escape-routes"],
    queryFn: () => fetch("/api/mig/security/escape-routes", { headers: MS5_HEADERS }).then(r => r.json()),
    refetchOnWindowFocus: false,
    enabled: ms5SubTab === "escape-routes",
  });

  const intentValidationQuery = useQuery<{ ok: boolean; intent_validation: any }>({
    queryKey: ["/api/mig/security/intent-validation"],
    queryFn: () => fetch("/api/mig/security/intent-validation", { headers: MS5_HEADERS }).then(r => r.json()),
    refetchOnWindowFocus: false,
    enabled: ms5SubTab === "intent-validation",
  });

  const testsQuery = useQuery<{ ok: boolean; tests: any[]; total: number }>({
    queryKey: ["/api/mig/security/tests"],
    queryFn: () => fetch("/api/mig/security/tests", { headers: MS5_HEADERS }).then(r => r.json()),
    refetchOnWindowFocus: false,
    enabled: ms5SubTab === "tests",
  });

  const patchesQuery = useQuery<{ ok: boolean; patches: any[]; total: number }>({
    queryKey: ["/api/mig/security/patches"],
    queryFn: () => fetch("/api/mig/security/patches", { headers: MS5_HEADERS }).then(r => r.json()),
    refetchOnWindowFocus: false,
    enabled: ms5SubTab === "patches",
  });

  const recentMergesQuery = useQuery<{ ok: boolean; merges: { patch: any; validation: any | null }[] }>({
    queryKey: ["/api/mig/security/merges/recent"],
    queryFn: () => fetch("/api/mig/security/merges/recent", { headers: MS5_HEADERS }).then(r => r.json()),
    refetchOnWindowFocus: false,
    enabled: ms5SubTab === "merges",
  });

  const reviewMutation = useMutation({
    mutationFn: async () => {
      const res = await fetch("/api/mig/security/review", { method: "POST", headers: MS5_HEADERS });
      return res.json();
    },
    onSuccess: (data: any) => {
      if (data.ok) {
        toast({ title: "MS5 Review complete", description: `Score: ${data.report?.overall_score ?? "—"}/100 (${data.report?.overall_grade ?? "—"})` });
        queryClient.invalidateQueries({ queryKey: ["/api/mig/security/report"] });
        queryClient.invalidateQueries({ queryKey: ["/api/mig/security/history"] });
        queryClient.invalidateQueries({ queryKey: ["/api/mig/security/findings"] });
        queryClient.invalidateQueries({ queryKey: ["/api/mig/security/escape-routes"] });
        queryClient.invalidateQueries({ queryKey: ["/api/mig/security/intent-validation"] });
        queryClient.invalidateQueries({ queryKey: ["/api/mig/security/tests"] });
        queryClient.invalidateQueries({ queryKey: ["/api/mig/security/patches"] });
      } else {
        toast({ variant: "destructive", title: "Review failed", description: data.error ?? "Unknown error" });
      }
    },
    onError: (err: any) => {
      toast({ variant: "destructive", title: "Review failed", description: err.message });
    },
  });

  const acknowledgeMutation = useMutation({
    mutationFn: async ({ finding_id, acknowledged_by }: { finding_id: string; acknowledged_by: string }) => {
      const res = await fetch("/api/mig/security/remediate", {
        method: "POST",
        headers: MS5_HEADERS,
        body: JSON.stringify({ finding_id, acknowledged_by }),
      });
      return res.json();
    },
    onSuccess: (data: any) => {
      if (data.ok) {
        toast({ title: "Finding acknowledged" });
        queryClient.invalidateQueries({ queryKey: ["/api/mig/security/findings"] });
      } else {
        toast({ variant: "destructive", title: "Acknowledge failed", description: data.error ?? "Unknown" });
      }
      setAcknowledgingId(null);
    },
    onError: () => setAcknowledgingId(null),
  });

  const patchActionMutation = useMutation({
    mutationFn: async ({ id, action }: { id: number; action: "approve" | "reject" | "queue" | "merge" }) => {
      const res = await fetch(`/api/mig/security/patches/${id}/${action}`, { method: "POST", headers: MS5_HEADERS });
      return res.json();
    },
    onSuccess: (data: any, vars: any) => {
      if (data.ok) {
        const msgs: Record<string, string> = { approve: "Patch approved", reject: "Patch rejected", queue: "Patch queued for merge", merge: "Patch merged — post-merge validation complete" };
        toast({ title: msgs[vars.action] ?? "Done" });
        queryClient.invalidateQueries({ queryKey: ["/api/mig/security/patches"] });
        if (vars.action === "merge") {
          queryClient.invalidateQueries({ queryKey: ["/api/mig/security/report"] });
          queryClient.invalidateQueries({ queryKey: ["/api/mig/security/findings"] });
        }
      } else {
        toast({ variant: "destructive", title: "Action failed", description: data.error ?? "Unknown" });
      }
      setActingPatchId(null);
    },
    onError: (err: any) => {
      toast({ variant: "destructive", title: "Action failed", description: err.message });
      setActingPatchId(null);
    },
  });

  const report = reportQuery.data?.report;
  const history = historyQuery.data?.history ?? [];
  const liveFindings: MS5Finding[] = findingsQuery.data?.findings ?? [];
  const certification = (report as any)?.certification ?? null;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="space-y-1">
          <h3 className="text-sm font-semibold flex items-center gap-2">
            <ShieldQuestion className="h-4 w-4 text-primary" />
            MS5 — MCP Security Five-Layer Model
            {certification && <CertificationBadge state={certification.state} />}
          </h3>
          <p className="text-xs text-muted-foreground">
            Certification authority for MCP Servers — attack surface analysis, escape route detection, automated testing, and one-click patch & merge workflow.
          </p>
          {certification && (
            <div className="text-xs text-muted-foreground">
              {certification.production_promotion_allowed
                ? <span className="text-green-600 dark:text-green-400">✓ Production promotion allowed</span>
                : <span className="text-red-600 dark:text-red-400">✗ {certification.promotion_block_reason?.slice(0, 120)}</span>}
            </div>
          )}
        </div>
        <Button size="sm" onClick={() => reviewMutation.mutate()} disabled={reviewMutation.isPending} data-testid="button-run-ms5-review">
          {reviewMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Activity className="h-4 w-4 mr-1" />}
          Run Review
        </Button>
      </div>

      {reportQuery.isLoading && (
        <div className="flex items-center gap-2 text-muted-foreground text-sm py-8"><Loader2 className="h-4 w-4 animate-spin" /> Loading latest report…</div>
      )}

      {!reportQuery.isLoading && !report && (
        <Card>
          <CardContent className="py-10 text-center text-muted-foreground text-sm">
            <ShieldQuestion className="h-8 w-8 mx-auto mb-2 opacity-30" />
            No security reviews run yet. Click <strong>Run Review</strong> to generate the first MS5 report.
          </CardContent>
        </Card>
      )}

      {/* MS5 Sub-tab navigation */}
      {(report || ms5SubTab !== "scorecard") && (
        <div className="flex gap-1 flex-wrap border-b pb-1" data-testid="nav-ms5-subtabs">
          {[
            { id: "scorecard", label: "Scorecard", icon: <BarChart3 className="h-3.5 w-3.5" /> },
            { id: "escape-routes", label: "Escape Routes", icon: <Network className="h-3.5 w-3.5" /> },
            { id: "inventory", label: "Capability Inventory", icon: <ListChecks className="h-3.5 w-3.5" /> },
            { id: "intent-validation", label: "Intent Validation", icon: <Radar className="h-3.5 w-3.5" /> },
            { id: "tests", label: "Automated Tests", icon: <TestTube2 className="h-3.5 w-3.5" /> },
            { id: "patches", label: "Patch Queue", icon: <GitMerge className="h-3.5 w-3.5" /> },
            { id: "merges", label: "Recent Merges", icon: <GitMerge className="h-3.5 w-3.5" /> },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setMs5SubTab(tab.id)}
              className={`inline-flex items-center gap-1 px-3 py-1.5 rounded-sm text-xs font-medium transition-colors ${ms5SubTab === tab.id ? "bg-primary/10 text-primary" : "text-muted-foreground hover:text-foreground hover:bg-muted/50"}`}
              data-testid={`tab-ms5-${tab.id}`}
            >
              {tab.icon}{tab.label}
            </button>
          ))}
        </div>
      )}

      {/* Escape Routes sub-tab */}
      {ms5SubTab === "escape-routes" && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Network className="h-4 w-4" /> Escape Route Analysis
              {escapeRouteQuery.isLoading && <Loader2 className="h-3 w-3 animate-spin ml-1" />}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {escapeRouteQuery.isLoading
              ? <div className="text-xs text-muted-foreground py-4 text-center">Loading escape route graph…</div>
              : <EscapeRouteGraph analysis={escapeRouteQuery.data?.escape_route_analysis} />
            }
          </CardContent>
        </Card>
      )}

      {/* Intent Validation sub-tab */}
      {ms5SubTab === "intent-validation" && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Radar className="h-4 w-4" /> Per-Product Intent Validation
              {intentValidationQuery.isLoading && <Loader2 className="h-3 w-3 animate-spin ml-1" />}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {intentValidationQuery.isLoading
              ? <div className="text-xs text-muted-foreground py-4 text-center">Loading intent validation…</div>
              : <IntentValidationPanel validation={intentValidationQuery.data?.intent_validation} />
            }
          </CardContent>
        </Card>
      )}

      {/* Automated Tests sub-tab */}
      {ms5SubTab === "tests" && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <TestTube2 className="h-4 w-4" /> Automated Test Suite
              {testsQuery.isLoading && <Loader2 className="h-3 w-3 animate-spin ml-1" />}
              {!testsQuery.isLoading && <span className="text-xs text-muted-foreground ml-auto">{testsQuery.data?.total ?? 0} tests</span>}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {testsQuery.isLoading
              ? <div className="text-xs text-muted-foreground py-4 text-center">Loading tests…</div>
              : <AutomatedTestsPanel tests={testsQuery.data?.tests ?? []} />
            }
          </CardContent>
        </Card>
      )}

      {/* Patch Queue sub-tab */}
      {ms5SubTab === "patches" && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <GitMerge className="h-4 w-4" /> Patch Queue & Merge Assistant
              {patchesQuery.isLoading && <Loader2 className="h-3 w-3 animate-spin ml-1" />}
              {!patchesQuery.isLoading && <span className="text-xs text-muted-foreground ml-auto">{patchesQuery.data?.total ?? 0} patches</span>}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {patchesQuery.isLoading
              ? <div className="text-xs text-muted-foreground py-4 text-center">Loading patches…</div>
              : <PatchQueuePanel
                  patches={patchesQuery.data?.patches ?? []}
                  isActing={patchActionMutation.isPending}
                  onApprove={id => { setActingPatchId(id); patchActionMutation.mutate({ id, action: "approve" }); }}
                  onReject={id => { setActingPatchId(id); patchActionMutation.mutate({ id, action: "reject" }); }}
                  onQueue={id => { setActingPatchId(id); patchActionMutation.mutate({ id, action: "queue" }); }}
                  onMerge={id => { setActingPatchId(id); patchActionMutation.mutate({ id, action: "merge" }); }}
                />
            }
          </CardContent>
        </Card>
      )}

      {ms5SubTab === "merges" && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <GitMerge className="h-4 w-4" /> Recent Merges — Governance Simulation Log
              {recentMergesQuery.isLoading && <Loader2 className="h-3 w-3 animate-spin ml-1" />}
              {!recentMergesQuery.isLoading && (
                <span className="text-xs text-muted-foreground ml-auto">
                  {recentMergesQuery.data?.merges?.length ?? 0} applied
                </span>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {recentMergesQuery.isLoading ? (
              <div className="text-xs text-muted-foreground py-4 text-center">Loading merge history…</div>
            ) : !recentMergesQuery.data?.merges?.length ? (
              <div className="text-xs text-muted-foreground py-6 text-center">
                No patches have been applied yet. Apply patches from the Patch Queue tab to see them here.
              </div>
            ) : (
              <div className="space-y-3" data-testid="list-recent-merges">
                {recentMergesQuery.data.merges.map(({ patch, validation }, idx) => (
                  <div
                    key={patch.id}
                    className="border rounded-md p-3 text-xs space-y-1.5"
                    data-testid={`card-recent-merge-${patch.id}`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="font-medium text-foreground">
                        {patch.findingSummary ?? `Patch #${patch.id}`}
                      </div>
                      <span className="shrink-0 px-1.5 py-0.5 rounded text-[10px] font-mono bg-green-500/10 text-green-600 dark:text-green-400">
                        {patch.status ?? "MERGED"}
                      </span>
                    </div>
                    {patch.capabilityName && (
                      <div className="text-muted-foreground">
                        Capability: <span className="font-mono text-foreground">{patch.capabilityName}</span>
                      </div>
                    )}
                    {validation ? (
                      <div className="flex gap-4 flex-wrap pt-1 border-t border-border/50">
                        <div>
                          Score: <span className="font-mono">{validation.scoreBefore}</span>
                          <span className="mx-1">→</span>
                          <span className={`font-mono font-semibold ${validation.scoreAfter > validation.scoreBefore ? "text-green-600 dark:text-green-400" : "text-muted-foreground"}`}>
                            {validation.scoreAfter}
                          </span>
                        </div>
                        <div>
                          Cert: <span className="font-mono">{validation.certificationBefore}</span>
                          <span className="mx-1">→</span>
                          <span className="font-mono">{validation.certificationAfter}</span>
                        </div>
                        <div>
                          Findings resolved: <span className="font-semibold text-green-600 dark:text-green-400">
                            {(validation.validationReport as any)?.resolved_findings?.length ?? 0}
                          </span>
                        </div>
                      </div>
                    ) : (
                      <div className="text-muted-foreground pt-1 border-t border-border/50">
                        No post-apply validation report available.
                      </div>
                    )}
                    {patch.mergedAt && (
                      <div className="text-muted-foreground text-[10px]">
                        Applied: {new Date(patch.mergedAt).toLocaleString()}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {report && ms5SubTab === "scorecard" && (
        <>
          <Card data-testid="card-ms5-scorecard">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <BarChart3 className="h-4 w-4" /> Security Scorecard
                <span className="text-xs text-muted-foreground ml-auto">Generated: {new Date(report.generated_at).toLocaleString()}</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-6 flex-wrap">
                <div className="flex flex-col items-center gap-0.5 min-w-[72px]">
                  <span className={`text-4xl font-black leading-none ${gradeColor(report.overall_grade)}`} data-testid="text-ms5-overall-grade">{report.overall_grade}</span>
                  <span className="text-xs text-muted-foreground">Overall</span>
                  <span className="text-xs font-mono text-muted-foreground" data-testid="text-ms5-overall-score">{report.overall_score}/100</span>
                </div>
                <div className="h-10 w-px bg-border" />
                {(["layer1","layer2","layer3","layer4","layer5"] as const).map((layer) => {
                  const grade = (report.scorecard as any)?.layer_grades?.[layer] ?? "—";
                  const score = (report.scorecard as any)?.layer_scores?.[layer] ?? 0;
                  const lr = (report.layer_results ?? []).find((l: any) => l.layer === layer);
                  const shortName = lr?.layer_name?.replace(/^(Layer \d+ — |L\d — )/, "") ?? layer;
                  return (
                    <div key={layer} className="flex flex-col items-center gap-0.5 min-w-[52px]" data-testid={`card-ms5-${layer}`}>
                      <span className={`text-2xl font-bold leading-none ${gradeColor(grade)}`}>{grade}</span>
                      <span className="text-xs text-muted-foreground text-center leading-tight">{shortName}</span>
                      <span className="text-xs font-mono text-muted-foreground">{score}/100</span>
                    </div>
                  );
                })}
                <div className="h-10 w-px bg-border" />
                <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                  <span className="text-red-600 dark:text-red-400 font-semibold" data-testid="text-ms5-critical-count">⬤ Critical: {(report.scorecard as any)?.critical_finding_count ?? 0}</span>
                  <span className="text-orange-600 dark:text-orange-400 font-semibold" data-testid="text-ms5-high-count">⬤ High: {(report.scorecard as any)?.high_finding_count ?? 0}</span>
                  <span className="text-yellow-600 dark:text-yellow-400" data-testid="text-ms5-medium-count">⬤ Medium: {(report.scorecard as any)?.medium_finding_count ?? 0}</span>
                  <span className="text-blue-600 dark:text-blue-400" data-testid="text-ms5-low-count">⬤ Low: {(report.scorecard as any)?.low_finding_count ?? 0}</span>
                </div>
              </div>

              {/* Intent Coverage visual bar */}
              {(() => {
                const pct: number = (report.scorecard as any)?.intent_coverage_percentage ?? 0;
                const barColor = pct >= 80 ? "bg-green-500" : pct >= 50 ? "bg-yellow-500" : "bg-red-500";
                return (
                  <div className="mt-4 space-y-1" data-testid="chart-ms5-intent-coverage">
                    <div className="flex justify-between text-xs text-muted-foreground">
                      <span>🎯 Intent coverage</span>
                      <span className="font-semibold text-foreground">{pct}%</span>
                    </div>
                    <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
                      <div className={`h-full rounded-full transition-all ${barColor}`} style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })()}

              <div className="mt-3 flex flex-wrap gap-3 text-xs text-muted-foreground">
                <span>🧪 Test coverage: <strong className="text-foreground">{(report.scorecard as any)?.test_coverage_percentage ?? 0}%</strong></span>
                <span>🔒 Prompt security: <strong className="text-foreground">{report.prompt_security_score}/100</strong></span>
                <span>🔧 Self-healing: <strong className="text-foreground">{report.self_healing_score}/100</strong></span>
                {(report.drift_detection as any)?.has_drift && <span className="text-yellow-600 dark:text-yellow-400 font-medium">⚠ Drift detected since last review</span>}
              </div>
            </CardContent>
          </Card>

          {(report.layer_results ?? []).length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2"><TrendingUp className="h-4 w-4" /> Layer Summaries</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {(report.layer_results as any[]).map((lr: any) => (
                  <div key={lr.layer} className="flex items-start gap-3 p-2 rounded bg-muted/50" data-testid={`card-ms5-layer-summary-${lr.layer}`}>
                    <span className={`text-lg font-bold leading-none mt-0.5 w-8 shrink-0 ${gradeColor(lr.grade)}`}>{lr.grade}</span>
                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-semibold">{LAYER_LABELS[lr.layer] ?? lr.layer_name}</div>
                      <div className="text-xs text-muted-foreground mt-0.5">{lr.summary}</div>
                    </div>
                    <span className="text-xs text-muted-foreground shrink-0">{lr.score}/100</span>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {/* Capability Inventory table */}
          {(report.capability_inventory ?? []).length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <ListChecks className="h-4 w-4" /> Capability Inventory
                  <span className="text-xs text-muted-foreground ml-auto">{(report.capability_inventory as any[]).length} capabilities</span>
                  <button
                    className="text-xs text-primary underline ml-2"
                    onClick={() => setShowInventory(v => !v)}
                    data-testid="button-ms5-toggle-inventory"
                  >
                    {showInventory ? "Hide" : "Show"}
                  </button>
                </CardTitle>
              </CardHeader>
              {showInventory && (
                <CardContent className="p-0">
                  <div className="overflow-x-auto">
                    <Table data-testid="table-ms5-capability-inventory">
                      <TableHeader>
                        <TableRow>
                          <TableHead className="text-xs">Tool</TableHead>
                          <TableHead className="text-xs">Class</TableHead>
                          <TableHead className="text-xs">Risk</TableHead>
                          <TableHead className="text-xs">Intent covered</TableHead>
                          <TableHead className="text-xs">Gov. contract</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {(report.capability_inventory as any[]).map((cap: any) => {
                          const capName = cap.capability_name ?? cap.tool_name ?? "unknown";
                          return (
                          <TableRow key={capName} data-testid={`row-ms5-cap-${capName}`}>
                            <TableCell className="text-xs font-mono py-1">{capName}</TableCell>
                            <TableCell className="text-xs py-1">
                              <span className={`px-1.5 py-0.5 rounded text-xs ${
                                cap.classification === "admin" ? "bg-red-500/15 text-red-600 dark:text-red-400" :
                                cap.classification === "execution" ? "bg-amber-500/15 text-amber-600 dark:text-amber-400" :
                                "bg-blue-500/15 text-blue-600 dark:text-blue-400"
                              }`}>{cap.classification}</span>
                            </TableCell>
                            <TableCell className="text-xs py-1">
                              <span className={`${
                                cap.risk_level === "critical" ? "text-red-600 dark:text-red-400" :
                                cap.risk_level === "high" ? "text-orange-600 dark:text-orange-400" :
                                cap.risk_level === "medium" ? "text-yellow-600 dark:text-yellow-400" :
                                "text-muted-foreground"
                              }`}>{cap.risk_level ?? "—"}</span>
                            </TableCell>
                            <TableCell className="text-xs py-1">
                              {cap.has_intent_contract
                                ? <span className="text-green-600 dark:text-green-400">✓</span>
                                : <span className="text-red-500">✗</span>}
                            </TableCell>
                            <TableCell className="text-xs py-1">
                              {cap.has_test_coverage
                                ? <span className="text-green-600 dark:text-green-400">✓</span>
                                : <span className="text-muted-foreground">—</span>}
                            </TableCell>
                          </TableRow>
                          );
                        })}
                      </TableBody>
                    </Table>
                  </div>
                </CardContent>
              )}
            </Card>
          )}

          {/* Live Findings — from /api/mig/security/findings with acknowledge toggle */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <ClipboardList className="h-4 w-4" /> Findings
                {findingsQuery.isLoading
                  ? <Loader2 className="h-3 w-3 animate-spin ml-1" />
                  : <span className="ml-auto text-xs text-muted-foreground">{liveFindings.length} unresolved{(severityFilter || layerFilter) ? " (filtered)" : ""}</span>
                }
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex gap-2 mb-3 flex-wrap">
                <select className="text-xs border rounded px-2 py-1 bg-background" value={severityFilter} onChange={e => setSeverityFilter(e.target.value)} data-testid="select-ms5-severity-filter">
                  <option value="">All severities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="info">Info</option>
                </select>
                <select className="text-xs border rounded px-2 py-1 bg-background" value={layerFilter} onChange={e => setLayerFilter(e.target.value)} data-testid="select-ms5-layer-filter">
                  <option value="">All layers</option>
                  {(["layer1","layer2","layer3","layer4","layer5"] as const).map(l => (
                    <option key={l} value={l}>{LAYER_LABELS[l]}</option>
                  ))}
                </select>
                {(severityFilter || layerFilter) && (
                  <button className="text-xs text-muted-foreground underline" onClick={() => { setSeverityFilter(""); setLayerFilter(""); }}>Clear</button>
                )}
              </div>
              {liveFindings.length === 0 ? (
                <div className="text-center text-muted-foreground text-sm py-6">
                  <CheckCheck className="h-8 w-8 mx-auto mb-2 text-green-500 opacity-70" />
                  {findingsQuery.isLoading ? "Loading findings…" : "No unresolved findings."}
                </div>
              ) : (
                <div className="space-y-2">
                  {liveFindings.map((finding: MS5Finding) => (
                    <div
                      key={finding.id}
                      className={`rounded border p-3 cursor-pointer transition-colors ${expandedFinding === finding.id ? "border-primary/50 bg-primary/5" : "border-border hover:bg-muted/50"}`}
                      onClick={() => setExpandedFinding(expandedFinding === finding.id ? null : finding.id)}
                      data-testid={`card-ms5-finding-${finding.id}`}
                    >
                      <div className="flex items-center gap-2 flex-wrap">
                        <SeverityBadgeMs5 severity={finding.severity} />
                        <span className="text-xs bg-secondary text-secondary-foreground rounded px-1.5 py-0.5">{LAYER_LABELS[finding.layer] ?? finding.layer}</span>
                        <span className="text-xs font-medium flex-1 min-w-0 truncate">{(finding as any).title ?? finding.category}</span>
                        <button
                          className="shrink-0 text-xs px-2 py-0.5 rounded border border-border hover:bg-muted transition-colors disabled:opacity-50"
                          disabled={acknowledgingId === finding.id || acknowledgeMutation.isPending}
                          onClick={e => {
                            e.stopPropagation();
                            setAcknowledgingId(finding.id);
                            acknowledgeMutation.mutate({ finding_id: finding.id, acknowledged_by: "admin" });
                          }}
                          data-testid={`button-ms5-acknowledge-${finding.id}`}
                        >
                          {acknowledgingId === finding.id ? <Loader2 className="h-3 w-3 animate-spin inline" /> : "Acknowledge"}
                        </button>
                        <span className="text-muted-foreground shrink-0">{expandedFinding === finding.id ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}</span>
                      </div>
                      {expandedFinding === finding.id && (
                        <div className="mt-3 space-y-2 text-xs">
                          {finding.capability_name && <div><span className="text-muted-foreground font-medium">Capability: </span><span className="font-mono">{finding.capability_name}</span></div>}
                          <div>
                            <div className="text-muted-foreground font-medium mb-0.5">Evidence</div>
                            <div className="bg-muted rounded p-2 text-muted-foreground">{finding.evidence}</div>
                          </div>
                          <div>
                            <div className="text-muted-foreground font-medium mb-0.5">Recommendation</div>
                            <div className="bg-muted rounded p-2">{finding.recommendation}</div>
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {(report.remediation_recommendations ?? []).length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2"><ListChecks className="h-4 w-4" /> Remediation Roadmap</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {(report.remediation_recommendations as any[]).slice(0, 12).map((rec: any, i: number) => (
                    <div key={`${rec.finding_id}-${i}`} className="flex gap-3 p-2 rounded bg-muted/50" data-testid={`card-ms5-remediation-${i}`}>
                      <div className="shrink-0 mt-0.5">
                        {rec.priority === "immediate" && <span className="text-xs font-bold text-red-600 dark:text-red-400">NOW</span>}
                        {rec.priority === "high" && <span className="text-xs font-bold text-orange-600 dark:text-orange-400">HIGH</span>}
                        {rec.priority === "medium" && <span className="text-xs font-bold text-yellow-600 dark:text-yellow-400">MED</span>}
                        {rec.priority === "low" && <span className="text-xs font-bold text-blue-600 dark:text-blue-400">LOW</span>}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="text-xs font-semibold">{rec.action_title}</div>
                        <div className="text-xs text-muted-foreground mt-0.5">{rec.action_description}</div>
                        {rec.self_healing_eligible && <span className="inline-block mt-1 text-xs text-green-600 dark:text-green-400 font-medium">⚙ Self-healing eligible</span>}
                      </div>
                    </div>
                  ))}
                  {(report.remediation_recommendations ?? []).length > 12 && (
                    <p className="text-xs text-muted-foreground text-center py-1">… and {(report.remediation_recommendations ?? []).length - 12} more</p>
                  )}
                </div>
              </CardContent>
            </Card>
          )}

          {(report.drift_detection as any)?.has_drift && (
            <Card className="border-yellow-300 dark:border-yellow-700">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2 text-yellow-600 dark:text-yellow-400">
                  <AlertTriangle className="h-4 w-4" /> Drift Detected Since Last Review
                </CardTitle>
              </CardHeader>
              <CardContent className="text-xs space-y-2">
                {(report.drift_detection as any).new_capabilities?.length > 0 && <div><span className="font-medium text-green-600">New: </span>{(report.drift_detection as any).new_capabilities.join(", ")}</div>}
                {(report.drift_detection as any).removed_capabilities?.length > 0 && <div><span className="font-medium text-red-600">Removed: </span>{(report.drift_detection as any).removed_capabilities.join(", ")}</div>}
                {(report.drift_detection as any).schema_drift_capabilities?.length > 0 && <div><span className="font-medium text-orange-600">Schema drift: </span>{(report.drift_detection as any).schema_drift_capabilities.join(", ")}</div>}
                {(report.drift_detection as any).version_drift && <div className="font-medium text-orange-600">⚠ Server version drift detected</div>}
                {(report.drift_detection as any).credential_drift && <div className="font-medium text-red-600">🔑 Credential drift — audit immediately</div>}
              </CardContent>
            </Card>
          )}
        </>
      )}

      {/* Capability Inventory sub-tab */}
      {report && ms5SubTab === "inventory" && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <ListChecks className="h-4 w-4" /> Capability Inventory & Attack Surface
              <span className="text-xs text-muted-foreground ml-auto">{(report.capability_inventory as any[])?.length ?? 0} capabilities</span>
            </CardTitle>
          </CardHeader>
          {(report.capability_inventory as any[])?.length > 0 ? (
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <Table data-testid="table-ms5-capability-inventory-full">
                  <TableHeader>
                    <TableRow>
                      <TableHead className="text-xs">Tool</TableHead>
                      <TableHead className="text-xs">Class</TableHead>
                      <TableHead className="text-xs">Risk</TableHead>
                      <TableHead className="text-xs">Attack Vectors</TableHead>
                      <TableHead className="text-xs">Intent ✓</TableHead>
                      <TableHead className="text-xs">Tests ✓</TableHead>
                      <TableHead className="text-xs">Blast Radius</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(report.capability_inventory as any[]).map((cap: any) => {
                      const capName2 = cap.capability_name ?? cap.tool_name ?? "unknown";
                      const as_ = (report as any).attack_surface?.per_capability_surfaces?.find((s: any) => s.capability_name === capName2);
                      return (
                        <TableRow key={capName2} data-testid={`row-ms5-cap-full-${capName2}`}>
                          <TableCell className="text-xs font-mono py-1">{capName2}</TableCell>
                          <TableCell className="text-xs py-1">
                            <span className={`px-1.5 py-0.5 rounded text-xs ${
                              cap.classification === "admin" ? "bg-red-500/15 text-red-600 dark:text-red-400" :
                              cap.classification === "execution" ? "bg-amber-500/15 text-amber-600 dark:text-amber-400" :
                              "bg-blue-500/15 text-blue-600 dark:text-blue-400"
                            }`}>{cap.classification}</span>
                          </TableCell>
                          <TableCell className="text-xs py-1">
                            <span className={`${
                              cap.risk_level === "critical" ? "text-red-600 dark:text-red-400 font-semibold" :
                              cap.risk_level === "high" ? "text-orange-600 dark:text-orange-400 font-semibold" :
                              cap.risk_level === "medium" ? "text-yellow-600 dark:text-yellow-400" :
                              "text-muted-foreground"
                            }`}>{cap.risk_level ?? "—"}</span>
                          </TableCell>
                          <TableCell className="text-xs py-1">
                            <div className="flex flex-wrap gap-1">
                              {(as_?.attack_vectors ?? []).slice(0, 3).map((v: string, i: number) => (
                                <span key={i} className="px-1 py-0.5 rounded bg-muted text-muted-foreground text-xs">{v.replace(/_/g, " ")}</span>
                              ))}
                              {(as_?.attack_vectors ?? []).length === 0 && <span className="text-muted-foreground">—</span>}
                            </div>
                          </TableCell>
                          <TableCell className="text-xs py-1 text-center">
                            {cap.has_intent_contract
                              ? <span className="text-green-600 dark:text-green-400">✓</span>
                              : <span className="text-red-500">✗</span>}
                          </TableCell>
                          <TableCell className="text-xs py-1 text-center">
                            {cap.has_test_coverage
                              ? <span className="text-green-600 dark:text-green-400">✓</span>
                              : <span className="text-muted-foreground">—</span>}
                          </TableCell>
                          <TableCell className="text-xs py-1">
                            {as_?.blast_radius_score != null
                              ? <span className={`font-mono ${as_.blast_radius_score >= 7 ? "text-red-600 dark:text-red-400 font-bold" : as_.blast_radius_score >= 4 ? "text-orange-600 dark:text-orange-400" : "text-muted-foreground"}`}>{as_.blast_radius_score}/10</span>
                              : <span className="text-muted-foreground">—</span>}
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          ) : (
            <CardContent className="py-8 text-center text-muted-foreground text-sm">
              <ListChecks className="h-8 w-8 mx-auto mb-2 opacity-30" />
              No capability inventory. Run a Review to populate it.
            </CardContent>
          )}
        </Card>
      )}

      {history.length > 0 && ms5SubTab === "scorecard" && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <ScrollText className="h-4 w-4" /> Review History
              <div className="ml-auto"><TrendSparkline history={history} /></div>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Date</TableHead>
                  <TableHead>Score</TableHead>
                  <TableHead>Grade</TableHead>
                  <TableHead>Report ID</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {history.map((h) => (
                  <TableRow key={h.report_id} data-testid={`row-ms5-history-${h.report_id}`}>
                    <TableCell className="text-xs">{new Date(h.generated_at).toLocaleString()}</TableCell>
                    <TableCell className="text-xs font-mono">{h.overall_score}/100</TableCell>
                    <TableCell><span className={`font-bold text-sm ${gradeColor(h.grade)}`}>{h.grade}</span></TableCell>
                    <TableCell className="text-xs font-mono text-muted-foreground truncate max-w-[180px]">{h.report_id}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

type McpKeyOption = { id: number; tenant_id: string; display_name: string; key_prefix: string; status: string; classification: string };

const CLASSIFICATION_BADGE_MIG: Record<string, string> = {
  read_only: "bg-blue-500/15 text-blue-600 dark:text-blue-400",
  execution: "bg-amber-500/15 text-amber-600 dark:text-amber-400",
  admin: "bg-red-500/15 text-red-600 dark:text-red-400",
};

export function NewAgentForm({
  onSubmit,
  submitting,
  defaultAgentId,
  mcpKeys,
  linkedKeyIds,
}: {
  onSubmit: (body: Record<string, unknown>) => void;
  submitting: boolean;
  defaultAgentId?: string;
  mcpKeys?: McpKeyOption[];
  linkedKeyIds?: Set<number>;
}) {
  const [selectedKeyId, setSelectedKeyId] = useState<number | null>(null);
  const [agentId, setAgentId] = useState(defaultAgentId ?? "");
  const [displayName, setDisplayName] = useState("");
  const [trustLevel, setTrustLevel] = useState("standard");
  const [riskZone, setRiskZone] = useState("medium");

  const activeKeys = (mcpKeys ?? []).filter(k => k.status === "active");
  const selectableKeys = activeKeys.filter(k => !(linkedKeyIds?.has(k.id)));
  const hasKeyPicker = activeKeys.length > 0;

  function selectKey(key: McpKeyOption) {
    if (selectedKeyId === key.id) {
      setSelectedKeyId(null);
      setAgentId(defaultAgentId ?? "");
      setDisplayName("");
    } else {
      setSelectedKeyId(key.id);
      setAgentId((key.key_prefix ?? "").replace(/^mcp_/, ""));
      setDisplayName(key.display_name);
    }
  }

  const canSubmit = !!agentId.trim() && !!displayName.trim() && !submitting;

  return (
    <div className="space-y-4">
      {hasKeyPicker ? (
        <div>
          <Label className="mb-2 block">Select MCP Key</Label>
          <p className="text-xs text-muted-foreground mb-2">
            Import an existing MCP API key that was issued before server-owned MIG registration.
          </p>
          <div className="space-y-2 max-h-52 overflow-y-auto border rounded-md p-2">
            {selectableKeys.length === 0 && activeKeys.length > 0 ? (
              <p className="text-xs text-muted-foreground italic px-2 py-3 text-center">
                All active keys are already imported into MIG.
              </p>
            ) : (
              activeKeys.map((key) => {
                const isLinked = linkedKeyIds?.has(key.id) ?? false;
                const isSelected = selectedKeyId === key.id;
                return (
                  <button
                    key={key.id}
                    type="button"
                    disabled={isLinked}
                    className={`w-full text-left rounded-md border px-3 py-2 transition-colors ${
                      isLinked
                        ? "border-border opacity-50 cursor-not-allowed bg-muted/30"
                        : isSelected
                          ? "border-primary bg-primary/5"
                          : "border-border hover:bg-muted/50"
                    }`}
                    onClick={() => !isLinked && selectKey(key)}
                    data-testid={`button-select-mcp-key-${key.id}`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div>
                        <div className="text-sm font-medium">{key.display_name}</div>
                        <div className="text-xs font-mono text-muted-foreground">{key.key_prefix}…</div>
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0">
                        {isLinked && (
                          <Badge className="bg-muted text-muted-foreground text-xs" data-testid={`badge-linked-key-${key.id}`}>
                            Linked
                          </Badge>
                        )}
                        <Badge className={CLASSIFICATION_BADGE_MIG[key.classification] ?? "bg-muted text-muted-foreground"}>
                          {key.classification}
                        </Badge>
                      </div>
                    </div>
                  </button>
                );
              })
            )}
          </div>
          {selectedKeyId === null && selectableKeys.length > 0 && (
            <p className="text-xs text-muted-foreground mt-1 italic">
              Select an existing MCP client to import.
            </p>
          )}
        </div>
      ) : null}

      {!hasKeyPicker && (
        <div>
          <Label htmlFor="agent-id">Agent ID</Label>
          <Input
            id="agent-id"
            value={agentId}
            onChange={(e) => setAgentId(e.target.value)}
            placeholder="byolab-agent-01"
            data-testid="input-agent-id"
          />
        </div>
      )}
      {!hasKeyPicker && (
        <div>
          <Label htmlFor="display-name">Display Name</Label>
          <Input
            id="display-name"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            placeholder="Byolab Autonomous Agent"
            data-testid="input-display-name"
          />
        </div>
      )}
      {hasKeyPicker && selectedKeyId !== null && (
        <div className="rounded-md border bg-muted/30 p-3 space-y-1 text-sm">
          <div className="flex justify-between items-center">
            <span className="text-xs text-muted-foreground">Agent ID</span>
            <code className="font-mono text-xs bg-muted px-1.5 py-0.5 rounded" data-testid="text-derived-agent-id">{agentId}</code>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-xs text-muted-foreground">Display Name</span>
            <span className="text-sm" data-testid="text-derived-display-name">{displayName}</span>
          </div>
        </div>
      )}
      {hasKeyPicker && selectedKeyId === null && (
        <p className="text-xs text-amber-600 dark:text-amber-400 flex items-center gap-1.5">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
          Select a key above to identify the MCP client.
        </p>
      )}
      <div>
        <Label>Trust Level</Label>
        <Select value={trustLevel} onValueChange={setTrustLevel}>
          <SelectTrigger data-testid="select-trust-level"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="standard">Standard</SelectItem>
            <SelectItem value="elevated">Elevated</SelectItem>
            <SelectItem value="privileged">Privileged</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <div>
        <Label>Max Allowed Risk Zone</Label>
        <Select value={riskZone} onValueChange={setRiskZone}>
          <SelectTrigger data-testid="select-risk-zone"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="low">Low</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <Button
        className="w-full"
        disabled={!canSubmit}
        data-testid="button-submit-agent"
        onClick={() => onSubmit({ mcpKeyId: selectedKeyId, clientType: "mcp", agentId: agentId.trim(), displayName: displayName.trim(), trustLevel, allowedRiskZones: [riskZone] })}
      >
        {submitting ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Plus className="h-4 w-4 mr-2" />}
        Import MCP Client
      </Button>
    </div>
  );
}

function ConnectivityContractCard({
  agentId,
  displayName,
  ticketSecret,
  onDismiss,
}: {
  agentId: string;
  displayName: string;
  ticketSecret: string;
  onDismiss: () => void;
}) {
  const { toast } = useToast();
  const origin = typeof window !== "undefined" ? window.location.origin : "";
  const mcpEndpoint = `${origin}/api/mcp`;
  const migEndpoint = `${origin}/api/mig/admin/tickets`;

  const jsonConfig = JSON.stringify(
    {
      mcpEndpoint,
      migEndpoint,
      agentId,
      ticketSecret: ticketSecret || "<shown once at registration>",
      note: "Use agentId + intentId to create a ticket via POST /api/mig/admin/tickets",
    },
    null,
    2
  );

  const curlSnippet = `# 1. Create a MIG ticket (supply agentId + intentId)
curl -s -X POST "${migEndpoint}" \\
  -H "Content-Type: application/json" \\
  -H "x-tenant-id: default" \\
  -d '{"agentId":"${agentId}","intentId":"<your-intent-id>","sessionId":"sess_$(date +%s)"}'

# 2. Call the BRIPe MCP server with an MCP-API key
curl -s -X POST "${mcpEndpoint}" \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer <your-mcp-api-key>" \\
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'`;

  const allText = `=== MIG Remote Connectivity Contract ===
Agent: ${displayName}  (${agentId})

MCP endpoint:   ${mcpEndpoint}
MIG tickets:    ${migEndpoint}
Agent ID:       ${agentId}
Ticket secret:  ${ticketSecret || "(not shown — already registered)"}

JSON config:
${jsonConfig}

cURL:
${curlSnippet}`;

  function copyAll() {
    navigator.clipboard.writeText(allText).then(() => {
      toast({ title: "Connectivity contract copied" });
    });
  }

  return (
    <Card className="border-yellow-500/50 bg-yellow-500/5" data-testid="card-connectivity-contract">
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between">
          <CardTitle className="text-base flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-yellow-500" />
            Remote Connectivity Contract — diagnostic export
          </CardTitle>
          <div className="flex gap-2">
            <Button size="sm" variant="outline" onClick={copyAll} data-testid="button-copy-connectivity-contract">
              <Copy className="h-3.5 w-3.5 mr-1" /> Copy all
            </Button>
            <Button size="sm" variant="ghost" onClick={onDismiss} data-testid="button-dismiss-connectivity-contract">
              ✕
            </Button>
          </div>
        </div>
        <p className="text-xs text-muted-foreground mt-1">
          Developer / diagnostic export only — this legacy connectivity material is not the normal onboarding path. The ticket secret is shown <strong>once</strong> and cannot be retrieved again.
        </p>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          <div>
            <div className="text-xs font-medium text-muted-foreground mb-0.5">Agent</div>
            <div className="font-mono text-xs bg-muted rounded px-2 py-1" data-testid="text-contract-agent-name">{displayName}</div>
          </div>
          <div>
            <div className="text-xs font-medium text-muted-foreground mb-0.5">Agent ID</div>
            <div className="font-mono text-xs bg-muted rounded px-2 py-1" data-testid="text-contract-agent-id">{agentId}</div>
          </div>
          <div>
            <div className="text-xs font-medium text-muted-foreground mb-0.5 flex items-center gap-1">
              <KeyRound className="h-3 w-3" /> MCP Endpoint
            </div>
            <div className="font-mono text-xs bg-muted rounded px-2 py-1 break-all" data-testid="text-contract-mcp-endpoint">{mcpEndpoint}</div>
          </div>
          <div>
            <div className="text-xs font-medium text-muted-foreground mb-0.5 flex items-center gap-1">
              <ShieldCheck className="h-3 w-3" /> MIG Ticket Endpoint
            </div>
            <div className="font-mono text-xs bg-muted rounded px-2 py-1 break-all" data-testid="text-contract-mig-endpoint">{migEndpoint}</div>
          </div>
        </div>

        <div>
          <div className="text-xs font-medium text-muted-foreground mb-0.5 flex items-center gap-1">
            <Lock className="h-3 w-3 text-yellow-500" /> Ticket Secret <span className="text-yellow-500 font-semibold">(one-time)</span>
          </div>
          <div className="font-mono text-xs bg-muted rounded px-2 py-1 break-all text-yellow-600 dark:text-yellow-400" data-testid="text-contract-ticket-secret">{ticketSecret}</div>
        </div>

        <div>
          <div className="text-xs font-medium text-muted-foreground mb-1">JSON Config Snippet</div>
          <pre className="text-xs bg-muted rounded p-2 overflow-x-auto whitespace-pre-wrap" data-testid="text-contract-json-config">{jsonConfig}</pre>
        </div>

        <div>
          <div className="text-xs font-medium text-muted-foreground mb-1">cURL — create ticket + call MCP server</div>
          <pre className="text-xs bg-muted rounded p-2 overflow-x-auto whitespace-pre-wrap" data-testid="text-contract-curl">{curlSnippet}</pre>
        </div>
      </CardContent>
    </Card>
  );
}
/** Authenticated onboarding is deliberately separate from legacy tenant-header APIs. */
async function onboardingRequest(url: string, method = "GET", body?: unknown) {
  const res = await fetchWithAuth(url, {
    method,
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${res.status}: ${(await res.text()) || res.statusText}`);
  return res;
}

export interface RegisteredMigClient {
  component_id: string;
  identity?: string;
  display_name?: string;
  client_class: "AGENT" | "MCP";
  status: string;
  onboarding_method?: string;
  trust_level?: string;
  max_risk_zone?: string;
  registration_origin?: string;
  handshake_status?: string;
  risk_zone?: string;
  lifecycle_status?: string;
  mcp_name?: string;
  mcp_class?: string;
  authority?: MigCredentialAuthorityComparison;
  credential?: {
    masked: string;
    class: "AGENT" | "MCP";
    tenant_id: string;
    status: string;
    assigned_authority?: MigCredentialAuthorityProjection;
  };
}

export interface MigOnboardingCandidate {
  candidate_id?: string;
  id?: string;
  identity?: string;
  display_name?: string;
  source?: string;
  endpoint?: string;
  capabilities?: string[];
  auth_hints?: string[];
  evidence?: string[] | string;
  trust_level?: string;
  max_risk_zone?: string;
  client_class?: "AGENT" | "MCP";
  status?: string;
  onboarding_method?: string;
  principal_id?: string;
  origin_user_id?: string;
  authority?: MigCredentialAuthorityComparison;
}

/** Administrative projection only. Authority and credential material remain server-owned. */
export interface IncomingMcpRegistrationRequest {
  request_id?: string;
  candidate_id?: string;
  id?: string;
  origin?: string;
  endpoint?: string;
  identity?: string;
  mcp_name?: string;
  capabilities?: string[];
  handshake_result?: string;
  handshake_status?: string;
  handshake?: string;
  current_ceiling?: string;
  requested_ceiling?: string;
  status?: string;
  authority?: MigCredentialAuthorityComparison;
}

type OnboardingMode = "manual" | "nearby" | "network" | "import";
function requestId(request: IncomingMcpRegistrationRequest) {
  return request.request_id ?? request.candidate_id ?? request.id ?? "";
}

function HandshakeIcon() {
  return <GitMerge className="h-4 w-4 text-primary" aria-hidden="true" />;
}

function AuthorityValues({ values }: { values: string[] }) {
  return <span className="break-words">{values.length ? values.join(", ") : "None assigned"}</span>;
}

/** A display-only requested-versus-assigned ceiling; it never evaluates authority. */
function AuthorityComparison({ authority }: { authority?: MigCredentialAuthorityComparison }) {
  if (!authority) return null;
  const rows: Array<[string, keyof MigCredentialAuthorityProjection]> = [
    ["Scopes", "scopes"], ["Allowed intents", "allowed_intents"], ["Allowed domains", "allowed_domains"],
    ["MCP targets", "allowed_mcp_targets"], ["Capabilities", "allowed_capabilities"],
    ["Resources", "allowed_resources"],
  ];
  return <div className="mt-3 rounded-md border p-3" data-testid="authority-comparison">
    <div className="grid grid-cols-[minmax(0,1fr)_minmax(0,1fr)] gap-3 text-xs">
      <p className="font-medium text-muted-foreground">REQUESTED</p><p className="font-medium text-muted-foreground">ASSIGNED CEILING</p>
      {rows.map(([label, key]) => <Fragment key={key}>
        <div><span className="text-muted-foreground">{label}</span><div><AuthorityValues values={authority.requested[key] as string[]} /></div></div>
        <div><span className="text-muted-foreground">{label}</span><div><AuthorityValues values={authority.assigned[key] as string[]} /></div></div>
      </Fragment>)}
      <div><span className="text-muted-foreground">Risk zone</span><div>{authority.requested.risk_zone_ceiling}</div></div>
      <div><span className="text-muted-foreground">Risk zone</span><div>{authority.assigned.risk_zone_ceiling}</div></div>
    </div>
    <p className="mt-2 text-xs text-muted-foreground">Requested values propose targets only. Assigned values are the credential maximum; final authority remains journey and MIG/BRIPe constrained.</p>
  </div>;
}

function HandshakeResult({ result }: { result: Record<string, unknown> }) {
  const value = (snake: string, camel: string) => result[snake] ?? result[camel];
  const endpoint = value("endpoint", "endpoint");
  const identity = value("identity", "mcpName") ?? value("mcp_name", "identity");
  const capabilities = value("capabilities", "capabilities");
  const status = String(value("handshake_status", "handshakeStatus") ?? value("status", "status") ?? "complete");
  return (
    <div className="mt-4 rounded-md border bg-muted/30 p-3 text-sm" data-testid="connect-register-result">
      <div className="flex items-center gap-2 font-medium"><CheckCircle2 className="h-4 w-4 text-green-600" /> Handshake {status}</div>
      <dl className="mt-2 grid gap-2 sm:grid-cols-2 text-xs">
        <div><dt className="text-muted-foreground">Endpoint</dt><dd className="font-mono break-all">{String(endpoint ?? "Verified")}</dd></div>
        <div><dt className="text-muted-foreground">MCP identity</dt><dd>{String(identity ?? "Verified")}</dd></div>
        <div><dt className="text-muted-foreground">Compatibility</dt><dd>{String(value("compatibility", "compatibility") ?? "Validated")}</dd></div>
        <div><dt className="text-muted-foreground">Lineage / outcomes</dt><dd>{String(value("lineage_support", "lineageSupport") ?? "Validated")} / {String(value("outcome_support", "outcomeSupport") ?? "Validated")}</dd></div>
        <div className="sm:col-span-2"><dt className="text-muted-foreground">Discovered capabilities</dt><dd>{Array.isArray(capabilities) ? capabilities.join(", ") || "None reported" : String(capabilities ?? "None reported")}</dd></div>
      </dl>
      <AuthorityComparison authority={value("authority", "authority") as MigCredentialAuthorityComparison | undefined} />
    </div>
  );
}

export function ClientOnboardingWorkspace() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [mode, setMode] = useState<OnboardingMode>("manual");
  const [endpoint, setEndpoint] = useState("");
  const [identity, setIdentity] = useState("");
  const [componentId, setComponentId] = useState("");
  const [principalId, setPrincipalId] = useState("");
  const [clientClass, setClientClass] = useState<"AGENT" | "MCP">("MCP");
  const [originUserId, setOriginUserId] = useState("");
  const [capabilities, setCapabilities] = useState("");
  const [authHints, setAuthHints] = useState("");
  const [trustLevel, setTrustLevel] = useState("");
  const [maxRiskZone, setMaxRiskZone] = useState("");
  const [approvedScope, setApprovedScope] = useState("");
  const [port, setPort] = useState("");
  const [observations, setObservations] = useState("[]");
  const [apiAuth, setApiAuth] = useState("");
  const [candidateOrigins, setCandidateOrigins] = useState<Record<string, string>>({});
  const [selected, setSelected] = useState<MigOnboardingCandidate | null>(null);
  const [credential, setCredential] = useState<{ client: string; secret: string } | null>(null);
  const [classFilter, setClassFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [validationChecks, setValidationChecks] = useState<Record<string, boolean>>({});
  const [connectEndpoint, setConnectEndpoint] = useState("");
  const [connectTrust, setConnectTrust] = useState("standard");
  const [connectRiskZone, setConnectRiskZone] = useState("low");
  const [connectCapabilities, setConnectCapabilities] = useState("");
  const [handshakeResult, setHandshakeResult] = useState<Record<string, unknown> | null>(null);

  const candidatesQuery = useQuery<MigOnboardingCandidate[]>({
    queryKey: ["/api/mig/admin/onboarding/candidates"],
    queryFn: async () => (await onboardingRequest("/api/mig/admin/onboarding/candidates")).json(),
  });
  const clientsQuery = useQuery<RegisteredMigClient[]>({
    queryKey: ["/api/mig/admin/clients"],
    queryFn: async () => (await onboardingRequest("/api/mig/admin/clients")).json(),
  });
  const incomingRequestsQuery = useQuery<IncomingMcpRegistrationRequest[]>({
    queryKey: ["/api/mig/admin/mcp/registrations"],
    queryFn: async () => (await onboardingRequest("/api/mig/admin/mcp/registrations")).json(),
  });
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/onboarding/candidates"] });
  const refreshSelected = async (candidateId: string) => {
    const rows: MigOnboardingCandidate[] = await (await onboardingRequest("/api/mig/admin/onboarding/candidates")).json();
    const fresh = rows.find(row => (row.candidate_id ?? row.id) === candidateId);
    if (fresh) setSelected({ ...fresh, origin_user_id: candidateOrigins[candidateId] ?? fresh.origin_user_id });
  };
  const discoverMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => onboardingRequest(`/api/mig/admin/onboarding/${mode === "nearby" ? "discover-nearby" : mode === "network" ? "scan-network" : mode === "import" ? "import" : "manual"}`, "POST", body),
    onSuccess: async (res) => {
      const payload = await res.json().catch(() => null);
      if (payload?.candidate) {
        const candidateId = payload.candidate.candidate_id ?? payload.candidate.candidateId ?? payload.candidate.id;
        if (candidateId && clientClass === "AGENT" && originUserId) setCandidateOrigins(current => ({ ...current, [candidateId]: originUserId }));
        setSelected({ ...payload.candidate, origin_user_id: candidateId ? candidateOrigins[candidateId] ?? (clientClass === "AGENT" ? originUserId : undefined) : undefined });
      }
      refresh();
      toast({ title: "Onboarding candidates updated" });
    },
    onError: (error: Error) => toast({ title: "Discovery failed", description: error.message, variant: "destructive" }),
  });
  const candidateAction = useMutation({
    mutationFn: ({ action, candidate }: { action: "identify" | "classify" | "validate" | "trust"; candidate: MigOnboardingCandidate }) =>
      onboardingRequest(
        `/api/mig/admin/onboarding/candidates/${encodeURIComponent(candidate.candidate_id ?? candidate.id ?? "")}/${action}`,
        "POST",
        action === "identify" ? { principal_id: candidate.principal_id ?? principalId } :
          action === "classify" ? { client_class: candidate.client_class ?? clientClass } :
            action === "validate" ? { validation: validationChecks } : {},
      ),
    onSuccess: async (res, variables) => {
      const updated = await res.json().catch(() => null);
      if (updated) setSelected(current => current ? { ...current, status: updated.state ?? updated.status ?? current.status } : current);
      refresh();
      await refreshSelected(variables.candidate.candidate_id ?? variables.candidate.id ?? "").catch(() => undefined);
    },
    onError: (error: Error) => toast({ title: "Candidate action failed", description: error.message, variant: "destructive" }),
  });
  const registerMutation = useMutation({
    mutationFn: (candidate: MigOnboardingCandidate) => onboardingRequest(`/api/mig/admin/registry/${encodeURIComponent(candidate.candidate_id ?? candidate.id ?? "")}/register`, "POST", {
      origin_user_id: candidate.origin_user_id,
    }),
    onSuccess: async (res, candidate) => {
      const payload = await res.json();
      queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/clients"] });
      setSelected(current => current ? { ...current, status: payload.candidate?.state ?? "registered" } : current);
      setCredential({ client: payload.client?.component_id ?? selected?.identity ?? "client", secret: payload.api_key ?? payload.credential ?? "" });
      await refreshSelected(candidate.candidate_id ?? candidate.id ?? "").catch(() => undefined);
      toast({ title: "Client registered" });
    },
    onError: (error: Error) => toast({ title: "Registration failed", description: error.message, variant: "destructive" }),
  });
  const revokeMutation = useMutation({
    mutationFn: (componentId: string) => onboardingRequest(`/api/mig/admin/clients/${encodeURIComponent(componentId)}/revoke`, "POST"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/clients"] });
      toast({ title: "Client safely revoked" });
    },
    onError: (error: Error) => toast({ title: "Revocation failed", description: error.message, variant: "destructive" }),
  });
  const connectMutation = useMutation({
    mutationFn: () => onboardingRequest("/api/mig/admin/mcp/connect-register", "POST", {
      endpoint: connectEndpoint,
      trust_level: connectTrust,
      max_risk_zone: connectRiskZone,
      capability_ceiling: connectCapabilities.split(",").map(value => value.trim()).filter(Boolean),
    }),
    onSuccess: async (res) => {
      const result = await res.json();
      setHandshakeResult(result);
      queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/clients"] });
      queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/onboarding/candidates"] });
      toast({ title: "MCP connected and registered", description: "Identity, compatibility, capabilities, lineage, and outcome support were checked." });
    },
    onError: (error: Error) => toast({ title: "Connect & Register failed", description: error.message, variant: "destructive" }),
  });
  const requestDecisionMutation = useMutation({
    mutationFn: ({ request, decision }: { request: IncomingMcpRegistrationRequest; decision: "approve_elevation" | "keep_restricted" | "reject" }) =>
      onboardingRequest(`/api/mig/admin/mcp/registrations/${encodeURIComponent(requestId(request))}/decision`, "POST", { decision }),
    onSuccess: (_res, variables) => {
      queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/mcp/registrations"] });
      queryClient.invalidateQueries({ queryKey: ["/api/mig/admin/clients"] });
      toast({ title: variables.decision === "reject" ? "Registration request rejected" : variables.decision === "approve_elevation" ? "Authority elevation approved" : "Client remains restricted" });
    },
    onError: (error: Error) => toast({ title: "Registration decision failed", description: error.message, variant: "destructive" }),
  });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    let parsedObservations: unknown = undefined;
    if (mode === "nearby") {
      try { parsedObservations = JSON.parse(observations); }
      catch { toast({ title: "Observations must be valid JSON", variant: "destructive" }); return; }
    }
    discoverMutation.mutate({
      identity, component_id: componentId || identity, principal_id: principalId, client_class: clientClass,
      origin_user_id: clientClass === "AGENT" ? originUserId : "", endpoint,
      capabilities: capabilities.split(",").map(value => value.trim()).filter(Boolean),
      auth_hints: authHints.split(",").map(value => value.trim()).filter(Boolean),
      trust_level: trustLevel, max_risk_zone: maxRiskZone,
      validation: validationChecks,
      approved_scopes: mode === "network" || mode === "import" ? [approvedScope] : [endpoint],
      ...(mode === "network" ? { target: endpoint, port } : {}),
      ...(mode === "nearby" ? { observations: JSON.stringify(parsedObservations) } : {}),
      ...(mode === "import" ? { registry_url: endpoint, auth_value: apiAuth } : {}),
    });
    if (mode === "import") setApiAuth("");
  };
  const candidates = candidatesQuery.data ?? [];
  const clients = (clientsQuery.data ?? []).filter(client =>
    (classFilter === "all" || client.client_class === classFilter) &&
    (statusFilter === "all" || client.status === statusFilter));

  const modeCards: Array<{ key: OnboardingMode; title: string; copy: string; icon: typeof Plus }> = [
    { key: "manual", title: "Add Manually", copy: "Enter a known client endpoint.", icon: Plus },
    { key: "nearby", title: "Discover Nearby", copy: "Find advertised local clients.", icon: Radar },
    { key: "network", title: "Scan Network", copy: "Scan an approved network target.", icon: Search },
    { key: "import", title: "Import from API", copy: "Import candidates from a source API.", icon: Upload },
  ];
  return <div className="space-y-6" data-testid="client-onboarding-workspace">
    <div>
      <h2 className="text-lg font-semibold">Client Onboarding</h2>
      <p className="text-sm text-muted-foreground">Connect MCP endpoints through the governed handshake. Trust and risk ceilings are decided by the server.</p>
    </div>
    <Card className="border-primary/40" data-testid="card-connect-register">
      <CardHeader className="pb-3"><CardTitle className="text-base flex items-center gap-2"><HandshakeIcon /> Connect &amp; Register</CardTitle>
        <p className="text-sm font-normal text-muted-foreground">The normal onboarding path. MIG verifies endpoint identity, MCP compatibility, capabilities, lineage and terminal-outcome support, then binds the existing credential class without exposing a stored secret.</p>
      </CardHeader>
      <CardContent>
        <div className="grid gap-3 md:grid-cols-4 items-end">
          <div className="space-y-1 md:col-span-2"><Label htmlFor="mcp-connect-endpoint">MCP endpoint</Label><Input id="mcp-connect-endpoint" value={connectEndpoint} onChange={e => setConnectEndpoint(e.target.value)} placeholder="https://mcp.example/endpoint" data-testid="input-connect-mcp-endpoint" /></div>
          <div className="space-y-1"><Label>Desired trust</Label><Select value={connectTrust} onValueChange={setConnectTrust}><SelectTrigger data-testid="select-connect-trust"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="restricted">Restricted</SelectItem><SelectItem value="standard">Standard</SelectItem><SelectItem value="elevated">Elevated</SelectItem></SelectContent></Select></div>
          <div className="space-y-1"><Label>Maximum risk zone</Label><Select value={connectRiskZone} onValueChange={setConnectRiskZone}><SelectTrigger data-testid="select-connect-risk-zone"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="low">Low</SelectItem><SelectItem value="medium">Medium</SelectItem><SelectItem value="high">High</SelectItem><SelectItem value="critical">Critical</SelectItem></SelectContent></Select></div>
           <div className="space-y-1 md:col-span-3"><Label htmlFor="mcp-connect-capabilities">Requested capabilities (comma-separated)</Label><Input id="mcp-connect-capabilities" value={connectCapabilities} onChange={e => setConnectCapabilities(e.target.value)} placeholder="search, read_document" data-testid="input-connect-capabilities" /></div>
          <Button className="md:col-start-4" disabled={!connectEndpoint.trim() || connectMutation.isPending} onClick={() => connectMutation.mutate()} data-testid="button-connect-register">{connectMutation.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Zap className="h-4 w-4 mr-1" />}Connect &amp; Register</Button>
        </div>
        {handshakeResult && <HandshakeResult result={handshakeResult} />}
      </CardContent>
    </Card>
    <div className="grid gap-3 md:grid-cols-4">
      {modeCards.map(({ key, title, copy, icon: Icon }) => <Card key={key} className={mode === key ? "border-primary" : ""}>
        <CardContent className="p-4"><Icon className="h-5 w-5 mb-2" /><h3 className="font-medium">{title}</h3><p className="text-xs text-muted-foreground mt-1">{copy}</p>
        <Button className="mt-3" size="sm" variant={mode === key ? "default" : "outline"} onClick={() => setMode(key)} data-testid={`button-onboarding-mode-${key}`}>Select</Button></CardContent>
      </Card>)}
    </div>
    <Card><CardContent className="p-4">
      <form onSubmit={submit} className="grid grid-cols-1 md:grid-cols-2 gap-3" data-testid={`form-onboarding-${mode}`}>
        {mode === "manual" && <>
          <div className="space-y-1"><Label htmlFor="client-identity">Display identity</Label><Input id="client-identity" value={identity} onChange={e => setIdentity(e.target.value)} required /></div>
          <div className="space-y-1"><Label htmlFor="client-component-id">Component ID</Label><Input id="client-component-id" value={componentId} onChange={e => setComponentId(e.target.value)} required /></div>
          <div className="space-y-1"><Label htmlFor="client-principal-id">Principal ID</Label><Input id="client-principal-id" value={principalId} onChange={e => setPrincipalId(e.target.value)} required /></div>
          <div className="space-y-1"><Label htmlFor="client-class">Client class</Label><Select value={clientClass} onValueChange={value => setClientClass(value as "AGENT" | "MCP")}><SelectTrigger id="client-class"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="AGENT">AGENT</SelectItem><SelectItem value="MCP">MCP</SelectItem></SelectContent></Select></div>
          {clientClass === "AGENT" && <div className="space-y-1"><Label htmlFor="client-origin-user">Origin user ID</Label><Input id="client-origin-user" value={originUserId} onChange={e => setOriginUserId(e.target.value)} required /></div>}
          <div className="md:col-span-2 space-y-2">
            <Label>Validation evidence supplied for review</Label>
            <div className="grid gap-2 sm:grid-cols-2">
              {(clientClass === "MCP"
                ? [["identity_auth", "Identity and authentication support"], ["outcome_return", "Terminal outcome return"], ["provenance_preservation", "Provenance preservation"], ["mig_continuation", "MIG-routed continuation"]]
                : [["identity_auth", "Identity and authentication support"], ["current_intent", "Current-intent submission"], ["governed_invocation", "Governed invocation"], ["mig_root_lineage", "MIG owns root lineage"]]
              ).map(([key, label]) => <label key={key} className="flex items-center gap-2 text-sm">
                <Checkbox checked={validationChecks[key] === true} onCheckedChange={checked => setValidationChecks(current => ({ ...current, [key]: checked === true }))} />
                {label}
              </label>)}
            </div>
          </div>
          <div className="space-y-1"><Label htmlFor="client-capabilities">Capabilities (comma-separated)</Label><Input id="client-capabilities" value={capabilities} onChange={e => setCapabilities(e.target.value)} /></div>
          <div className="space-y-1"><Label htmlFor="client-auth-hints">Auth hints (comma-separated)</Label><Input id="client-auth-hints" value={authHints} onChange={e => setAuthHints(e.target.value)} /></div>
          <div className="space-y-1"><Label htmlFor="client-trust-level">Requested trust level</Label><Input id="client-trust-level" value={trustLevel} onChange={e => setTrustLevel(e.target.value)} /></div>
          <div className="space-y-1"><Label htmlFor="client-risk-zone">Maximum risk zone</Label><Input id="client-risk-zone" value={maxRiskZone} onChange={e => setMaxRiskZone(e.target.value)} /></div>
        </>}
        {mode === "nearby" && <><div className="space-y-1"><Label htmlFor="nearby-identity">Observed identity</Label><Input id="nearby-identity" value={identity} onChange={e => setIdentity(e.target.value)} required /></div><div className="space-y-1 md:col-span-2"><Label htmlFor="client-observations">Bounded observations JSON</Label><textarea id="client-observations" className="w-full min-h-24 rounded border bg-background p-2 text-sm" value={observations} onChange={e => setObservations(e.target.value)} /><p className="text-xs text-muted-foreground">Only bounded observations are submitted for proximity discovery.</p></div></>}
        {mode === "network" && <><div className="space-y-1"><Label htmlFor="client-approved-scope">Approved scope</Label><Input id="client-approved-scope" value={approvedScope} onChange={e => setApprovedScope(e.target.value)} required placeholder="https://10.0.0.0/24" /></div><div className="space-y-1"><Label htmlFor="client-network-target">Network target</Label><Input id="client-network-target" value={endpoint} onChange={e => setEndpoint(e.target.value)} required /></div><div className="space-y-1"><Label htmlFor="client-port">Port</Label><Input id="client-port" type="number" value={port} onChange={e => setPort(e.target.value)} required /></div></>}
        {mode === "import" && <><div className="space-y-1"><Label htmlFor="client-registry-url">Registry URL</Label><Input id="client-registry-url" value={endpoint} onChange={e => setEndpoint(e.target.value)} required placeholder="https://registry.example" /></div><div className="space-y-1"><Label htmlFor="client-api-auth">Optional API auth value</Label><Input id="client-api-auth" type="password" value={apiAuth} onChange={e => setApiAuth(e.target.value)} /><p className="text-xs text-yellow-600">Used for this import only; it is not stored or rendered.</p></div><div className="space-y-1"><Label htmlFor="client-import-scope">Approved scope</Label><Input id="client-import-scope" value={approvedScope} onChange={e => setApprovedScope(e.target.value)} required /></div></>}
        {mode === "nearby" && <div className="space-y-1"><Label htmlFor="client-endpoint">Observed endpoint (optional)</Label><Input id="client-endpoint" value={endpoint} onChange={e => setEndpoint(e.target.value)} /></div>}
        {mode === "manual" && <div className="space-y-1"><Label htmlFor="client-endpoint">Endpoint</Label><Input id="client-endpoint" value={endpoint} onChange={e => setEndpoint(e.target.value)} required placeholder="https://…" /></div>}
        <Button type="submit" className="w-fit self-end" disabled={discoverMutation.isPending} data-testid="button-run-onboarding">{discoverMutation.isPending && <Loader2 className="h-4 w-4 mr-1 animate-spin" />}{mode === "manual" ? "Add candidate" : "Run discovery"}</Button>
      </form>
    </CardContent></Card>
    <div className="grid gap-4 lg:grid-cols-2">
      <Card><CardHeader><CardTitle className="text-base">Candidates</CardTitle></CardHeader><CardContent className="space-y-2">
        {candidatesQuery.isLoading ? <Loader2 className="h-5 w-5 animate-spin" /> : candidates.length === 0 ? <p className="text-sm text-muted-foreground">No candidates found.</p> : candidates.map(candidate => <button key={candidate.candidate_id ?? candidate.id} className="block text-left border rounded p-3 w-full hover:bg-muted" onClick={() => setSelected({ ...candidate, origin_user_id: candidateOrigins[candidate.candidate_id ?? candidate.id ?? ""] ?? candidate.origin_user_id })} data-testid={`candidate-${candidate.candidate_id ?? candidate.id}`}>
          <div className="flex justify-between"><span className="font-medium">{candidate.display_name ?? candidate.identity}</span><StatusBadge status={candidate.status ?? "pending"} /></div><p className="font-mono text-xs text-muted-foreground mt-1">{candidate.endpoint}</p><p className="text-xs mt-1">Source: {candidate.source ?? "unknown"} · {candidate.client_class ?? "unclassified"}</p>
        </button>)}
      </CardContent></Card>
      <Card><CardHeader><CardTitle className="text-base flex gap-2 items-center"><Eye className="h-4 w-4" /> Candidate review</CardTitle></CardHeader><CardContent>
        {!selected ? <p className="text-sm text-muted-foreground">Select a candidate to inspect its evidence.</p> : <div className="space-y-3 text-sm" data-testid="candidate-detail">
          <dl className="grid grid-cols-2 gap-2"><dt className="text-muted-foreground">Identity</dt><dd>{selected.identity ?? selected.display_name}</dd><dt className="text-muted-foreground">Source</dt><dd>{selected.source ?? "unknown"}</dd><dt className="text-muted-foreground">Endpoint</dt><dd className="font-mono text-xs break-all">{selected.endpoint ?? "—"}</dd><dt className="text-muted-foreground">Capabilities</dt><dd>{(selected.capabilities ?? []).join(", ") || "None reported"}</dd><dt className="text-muted-foreground">Auth hints</dt><dd>{(selected.auth_hints ?? []).join(", ") || "None reported"}</dd><dt className="text-muted-foreground">Evidence</dt><dd>{Array.isArray(selected.evidence) ? selected.evidence.join("; ") : selected.evidence ?? "None reported"}</dd><dt className="text-muted-foreground">Trust level</dt><dd>{selected.trust_level ?? "Server pending"}</dd><dt className="text-muted-foreground">Max risk zone</dt><dd>{selected.max_risk_zone ?? "Server pending"}</dd></dl>
          <AuthorityComparison authority={selected.authority} />
          {(selected.status === "classified" || selected.status === "failed_validation") && <div className="grid gap-2 sm:grid-cols-2">
            {(selected.client_class === "MCP"
              ? [["identity_auth", "Identity and authentication support"], ["outcome_return", "Terminal outcome return"], ["provenance_preservation", "Provenance preservation"], ["mig_continuation", "MIG-routed continuation"]]
              : [["identity_auth", "Identity and authentication support"], ["current_intent", "Current-intent submission"], ["governed_invocation", "Governed invocation"], ["mig_root_lineage", "MIG owns root lineage"]]
            ).map(([key, label]) => <label key={key} className="flex items-center gap-2 text-sm">
              <Checkbox checked={validationChecks[key] === true} onCheckedChange={checked => setValidationChecks(current => ({ ...current, [key]: checked === true }))} />
              {label}
            </label>)}
          </div>}
          <div className="flex flex-wrap gap-2">
            {(selected.status === "discovered" || selected.status === "identified") && <div className="w-full grid gap-2 sm:grid-cols-2">
              <div className="space-y-1"><Label htmlFor="review-principal-id">Principal binding</Label><Input id="review-principal-id" value={principalId} onChange={e => setPrincipalId(e.target.value)} placeholder="Existing active principal ID" /></div>
              <div className="space-y-1"><Label htmlFor="review-client-class">Administrator classification</Label><Select value={clientClass} onValueChange={value => setClientClass(value as "AGENT" | "MCP")}><SelectTrigger id="review-client-class"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="AGENT">AGENT</SelectItem><SelectItem value="MCP">MCP</SelectItem></SelectContent></Select></div>
            </div>}
            {selected.status === "discovered" && <Button size="sm" variant="outline" onClick={() => candidateAction.mutate({ action: "identify", candidate: selected })} disabled={!selected.principal_id && !principalId} data-testid="button-identify-candidate">Identify</Button>}
            {selected.status === "identified" && <Button size="sm" variant="outline" onClick={() => candidateAction.mutate({ action: "classify", candidate: selected })} disabled={!selected.client_class && !clientClass} data-testid="button-classify-candidate">Classify</Button>}
            {(selected.status === "classified" || selected.status === "failed_validation") && <Button size="sm" variant="outline" onClick={() => candidateAction.mutate({ action: "validate", candidate: selected })} data-testid="button-validate-candidate"><CheckCheck className="h-4 w-4 mr-1" />Validate</Button>}
            {selected.status === "validated" && <Button size="sm" onClick={() => registerMutation.mutate(selected)} disabled={!selected.client_class || !selected.principal_id || (selected.client_class === "AGENT" && !selected.origin_user_id)} data-testid="button-register-candidate">Register</Button>}
            {selected.status === "registered" && <Button size="sm" variant="outline" onClick={() => candidateAction.mutate({ action: "trust", candidate: selected })} data-testid="button-trust-candidate"><ShieldPlus className="h-4 w-4 mr-1" />Trust</Button>}
          </div>
        </div>}
      </CardContent></Card>
    </div>
    <Card data-testid="card-incoming-registration-requests"><CardHeader><CardTitle className="text-base flex items-center gap-2"><GitPullRequest className="h-4 w-4" /> Incoming Registration Requests</CardTitle>
      <p className="text-sm font-normal text-muted-foreground">MCP-initiated requests remain restricted with a conservative ceiling until an authorized administrator records an elevation decision.</p>
    </CardHeader><CardContent>
      {incomingRequestsQuery.isLoading ? <Loader2 className="h-5 w-5 animate-spin" /> : (incomingRequestsQuery.data ?? []).filter(request => request.origin === "mcp_initiated").length === 0 ? <p className="text-sm text-muted-foreground">No incoming MCP registration requests.</p> : <div className="overflow-x-auto"><Table><TableHeader><TableRow><TableHead>Origin / endpoint</TableHead><TableHead>Capabilities</TableHead><TableHead>Handshake</TableHead><TableHead>Current / requested ceiling</TableHead><TableHead>Action</TableHead></TableRow></TableHeader><TableBody>
        {(incomingRequestsQuery.data ?? []).filter(request => request.origin === "mcp_initiated").map(request => <TableRow key={requestId(request)} data-testid={`row-registration-request-${requestId(request)}`}><TableCell><div>{request.mcp_name ?? request.identity ?? request.origin ?? "MCP request"}</div><div className="font-mono text-xs text-muted-foreground break-all">{request.endpoint ?? "—"}</div></TableCell><TableCell className="text-xs">{(request.capabilities ?? []).join(", ") || "None reported"}</TableCell><TableCell><StatusBadge status={request.handshake_result ?? request.handshake_status ?? request.handshake ?? "pending"} /></TableCell><TableCell className="text-xs"><div>{request.current_ceiling ?? "restricted"} / {request.requested_ceiling ?? "—"}</div><AuthorityComparison authority={request.authority} /></TableCell><TableCell><div className="flex flex-wrap gap-1"><Button size="sm" onClick={() => requestDecisionMutation.mutate({ request, decision: "approve_elevation" })} data-testid={`button-approve-elevation-${requestId(request)}`}>Approve Elevation</Button><Button size="sm" variant="outline" onClick={() => requestDecisionMutation.mutate({ request, decision: "keep_restricted" })} data-testid={`button-keep-restricted-${requestId(request)}`}>Keep Restricted</Button><Button size="sm" variant="destructive" onClick={() => requestDecisionMutation.mutate({ request, decision: "reject" })} data-testid={`button-reject-registration-${requestId(request)}`}>Reject</Button></div></TableCell></TableRow>)}
      </TableBody></Table></div>}
    </CardContent></Card>
    <Card><CardHeader><CardTitle className="text-base">Registered Clients</CardTitle></CardHeader><CardContent className="space-y-3">
      <div className="flex gap-2"><Select value={classFilter} onValueChange={setClassFilter}><SelectTrigger className="w-36"><SelectValue placeholder="Class" /></SelectTrigger><SelectContent><SelectItem value="all">All classes</SelectItem><SelectItem value="AGENT">AGENT</SelectItem><SelectItem value="MCP">MCP</SelectItem></SelectContent></Select><Select value={statusFilter} onValueChange={setStatusFilter}><SelectTrigger className="w-36"><SelectValue placeholder="Status" /></SelectTrigger><SelectContent><SelectItem value="all">All statuses</SelectItem><SelectItem value="active">Active</SelectItem><SelectItem value="revoked">Revoked</SelectItem></SelectContent></Select></div>
      <Table><TableHeader><TableRow><TableHead>Client</TableHead><TableHead>Credential</TableHead><TableHead>Origin</TableHead><TableHead>Handshake</TableHead><TableHead>Assigned ceiling</TableHead><TableHead>Status</TableHead><TableHead>Action</TableHead></TableRow></TableHeader><TableBody>{clients.map(client => <TableRow key={client.component_id} data-testid={`row-registered-client-${client.component_id}`}><TableCell><div>{client.mcp_name ?? client.display_name ?? client.identity ?? client.component_id}</div><div className="font-mono text-xs text-muted-foreground">{client.component_id}</div></TableCell><TableCell><div className="font-mono text-xs">{client.credential?.masked ?? "No active credential"}</div><div className="text-xs text-muted-foreground">{client.credential?.class ?? client.mcp_class ?? client.client_class} · {client.credential?.tenant_id ?? "—"}</div></TableCell><TableCell>{client.registration_origin ?? client.onboarding_method ?? "—"}</TableCell><TableCell><StatusBadge status={client.handshake_status ?? "legacy"} /></TableCell><TableCell className="text-xs"><div>{client.authority?.assigned.risk_zone_ceiling ?? client.risk_zone ?? client.max_risk_zone ?? "—"}</div><div className="text-muted-foreground">{client.authority?.assigned.allowed_capabilities.join(", ") || "No capabilities assigned"}</div></TableCell><TableCell><StatusBadge status={client.lifecycle_status ?? client.status} /></TableCell><TableCell>{client.status !== "revoked" && <Button size="sm" variant="destructive" onClick={() => { if (window.confirm("Revoke this client? Existing credentials will stop working.")) revokeMutation.mutate(client.component_id); }} data-testid={`button-revoke-client-${client.component_id}`}><ShieldOff className="h-3.5 w-3.5 mr-1" />Revoke</Button>}</TableCell></TableRow>)}</TableBody></Table>
      {clients.length === 0 && !clientsQuery.isLoading && <p className="text-sm text-muted-foreground">No registered clients match these filters.</p>}
    </CardContent></Card>
    <Dialog open={!!credential} onOpenChange={open => !open && setCredential(null)}><DialogContent><DialogHeader><DialogTitle>Credential — copy now</DialogTitle></DialogHeader><p className="text-sm text-muted-foreground">This credential is shown once. It is never rendered in the registered-client list.</p><div className="font-mono text-sm rounded bg-muted p-3 break-all" data-testid="text-onboarding-credential">{credential?.secret}</div><Button onClick={() => setCredential(null)} data-testid="button-dismiss-onboarding-credential">I copied it</Button></DialogContent></Dialog>
  </div>;
}
