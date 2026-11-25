import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  AlertCircle, Check, ChevronDown, Clipboard, Copy, FileJson, Fingerprint,
  KeyRound, RefreshCw, ShieldAlert, UserRoundCheck,
} from "lucide-react";
import type { MigHostOperatorRequestView } from "@shared/mig-host-operator";
import { fetchWithAuth } from "@/lib/queryClient";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

const REQUESTS_URL = "/api/mig/admin/host-operator-requests";
const CONTRACT_URL = "/api/mig/host-operator-requests/contract";

async function getJson<T>(url: string): Promise<T> {
  const response = await fetchWithAuth(url, { method: "GET", headers: { Accept: "application/json" } });
  if (!response.ok) {
    const detail = (await response.text()) || response.statusText;
    throw new Error(`${response.status}: ${detail}`);
  }
  return response.json() as Promise<T>;
}

export function formatHostOperatorContract(contract: unknown): string {
  return JSON.stringify(contract, null, 2) ?? "";
}

function StateBadge({ children, tone = "muted" }: { children: string; tone?: "muted" | "good" | "warning" | "bad" }) {
  const toneClass = {
    muted: "border-border bg-muted/60 text-muted-foreground",
    good: "border-emerald-700/20 bg-emerald-700/10 text-emerald-800 dark:text-emerald-300",
    warning: "border-amber-700/20 bg-amber-700/10 text-amber-900 dark:text-amber-300",
    bad: "border-destructive/20 bg-destructive/10 text-destructive",
  }[tone];
  return <Badge variant="outline" className={toneClass}>{children}</Badge>;
}

export function HostOperatorRequestCard({ request }: { request: MigHostOperatorRequestView }) {
  const approvalTone = request.approval_state === "approved"
    ? "good"
    : request.approval_state === "rejected" ? "bad" : "warning";

  return (
    <article className="rounded-lg border border-border/80 bg-card p-4" data-testid={`host-operator-request-${request.request_id}`}>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <p className="break-all font-mono text-sm font-semibold text-foreground">{request.principal_id}</p>
          <p className="mt-1 break-all font-mono text-xs text-muted-foreground">{request.client_id}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <StateBadge tone={approvalTone}>Review: {request.approval_state}</StateBadge>
          <StateBadge tone={request.registered ? "good" : "muted"}>Registration: {request.registered ? "registered" : "not registered"}</StateBadge>
        </div>
      </div>

      <dl className="mt-4 grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
        <div>
          <dt className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Requested scope</dt>
          <dd className="mt-1 break-words">{request.project} / {request.environment} <span className="text-muted-foreground">· {request.resource_scope}</span></dd>
        </div>
        <div>
          <dt className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Capability</dt>
          <dd className="mt-1 break-words font-mono text-xs">{request.capability_ids.length ? request.capability_ids.join(", ") : "None listed"}</dd>
        </div>
        <div className="sm:col-span-2">
          <dt className="flex items-center gap-1 text-xs font-medium uppercase tracking-wide text-muted-foreground"><Fingerprint className="h-3.5 w-3.5" /> Ed25519 public-key fingerprint</dt>
          <dd className="mt-1 break-all font-mono text-xs">{request.public_key_fingerprint || "Not available"}</dd>
          <p className="mt-1 text-xs text-muted-foreground">
            Key possession {request.key_ownership_verified ? "verified" : "not verified"}; the private key remains external.
          </p>
        </div>
      </dl>

      <div className="mt-4 grid gap-2 border-t border-border/70 pt-3 text-xs sm:grid-cols-3">
        <p className="flex items-start gap-1.5 text-muted-foreground"><UserRoundCheck className="mt-0.5 h-3.5 w-3.5 shrink-0" /> SmartDev enrollment: not verified by MIG</p>
        <p className="flex items-start gap-1.5 text-muted-foreground"><ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" /> Authorized execution: not verified</p>
        <p className="text-muted-foreground">Request state: <span className="font-medium text-foreground">{request.state}</span></p>
        <p className="text-muted-foreground sm:col-span-3">Execution contract: {request.execution_contract_available ? "available" : "not available"}</p>
      </div>
      {request.blockers.length > 0 && (
        <div className="mt-3 rounded-md border border-amber-700/20 bg-amber-700/5 p-3" data-testid="host-operator-blockers">
          <p className="text-xs font-semibold text-foreground">Blockers</p>
          <ul className="mt-1 list-inside list-disc space-y-1 text-xs text-muted-foreground">
            {request.blockers.map((blocker, index) => <li key={`${index}-${blocker}`} className="break-words">{blocker}</li>)}
          </ul>
        </div>
      )}
    </article>
  );
}

function HostOperatorRequestList() {
  const requestsQuery = useQuery({
    queryKey: [REQUESTS_URL],
    queryFn: () => getJson<MigHostOperatorRequestView[]>(REQUESTS_URL),
  });

  if (requestsQuery.isLoading) {
    return (
      <div className="space-y-3" aria-label="Loading host-operator requests" data-testid="host-operator-loading">
        <div className="h-20 animate-pulse rounded-lg bg-muted/70" />
        <div className="h-20 animate-pulse rounded-lg bg-muted/50" />
      </div>
    );
  }
  if (requestsQuery.isError) {
    return (
      <div className="flex flex-col gap-3 rounded-lg border border-destructive/25 bg-destructive/5 p-4 sm:flex-row sm:items-center sm:justify-between" role="alert" data-testid="host-operator-error">
        <div className="flex gap-2 text-sm"><AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" /><span>Request status could not be loaded. No registration or approval state is being assumed.</span></div>
        <Button variant="outline" size="sm" onClick={() => requestsQuery.refetch()}><RefreshCw className="mr-2 h-4 w-4" />Retry</Button>
      </div>
    );
  }

  const requests = requestsQuery.data ?? [];
  if (requests.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-border bg-muted/20 p-4" data-testid="host-operator-empty">
        <p className="text-sm font-medium">No host-operator requests</p>
        <p className="mt-1 text-sm text-muted-foreground">Simple MIG remains ready for endpoint + intents + automatic discovery. Identity review is separate and only applies when an operator registration request exists.</p>
      </div>
    );
  }
  return (
    <div className="space-y-3" data-testid="host-operator-request-list">
      {requests.map((request) => <HostOperatorRequestCard key={request.request_id} request={request} />)}
    </div>
  );
}

function AutomationContract() {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const contractQuery = useQuery({
    queryKey: [CONTRACT_URL],
    queryFn: () => getJson<unknown>(CONTRACT_URL),
    enabled: open,
    staleTime: 60_000,
  });

  async function copyContract() {
    if (!contractQuery.data) return;
    try {
      await navigator.clipboard.writeText(formatHostOperatorContract(contractQuery.data));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  }

  return (
    <section className="rounded-lg border border-border/80 bg-muted/20 p-4" data-testid="host-operator-contract">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-start gap-2.5">
          <span className="rounded-md bg-primary/10 p-2 text-primary"><FileJson className="h-4 w-4" /></span>
          <div>
            <h3 className="text-sm font-semibold">Automation contract</h3>
            <p className="mt-1 max-w-2xl text-xs text-muted-foreground">Fetch the live JSON contract for challenge + signed-request automation. It is the source of truth for endpoints, payloads, and signing details—no manual identity form or invented CLI steps.</p>
          </div>
        </div>
        <div className="flex shrink-0 gap-2">
          <Button variant="outline" size="sm" onClick={() => setOpen((value) => !value)} aria-expanded={open} data-testid="host-operator-contract-toggle">
            {open ? "Hide contract" : "View contract"} <ChevronDown className={`ml-2 h-4 w-4 transition-transform ${open ? "rotate-180" : ""}`} />
          </Button>
          {open && contractQuery.data && (
            <Button variant="outline" size="sm" onClick={copyContract} data-testid="host-operator-contract-copy">
              {copied ? <Check className="mr-2 h-4 w-4" /> : <Copy className="mr-2 h-4 w-4" />}{copied ? "Copied" : "Copy JSON"}
            </Button>
          )}
        </div>
      </div>
      {open && (
        <div className="mt-4">
          {contractQuery.isLoading ? (
            <div className="h-24 animate-pulse rounded-md bg-muted/70" aria-label="Loading automation contract" data-testid="host-operator-contract-loading" />
          ) : contractQuery.isError ? (
            <div className="flex items-center justify-between gap-3 rounded-md border border-destructive/25 bg-destructive/5 p-3 text-sm" role="alert" data-testid="host-operator-contract-error">
              <span className="flex items-center gap-2"><AlertCircle className="h-4 w-4 text-destructive" />The automation contract is unavailable.</span>
              <Button variant="outline" size="sm" onClick={() => contractQuery.refetch()}>Retry</Button>
            </div>
          ) : (
            <pre className="max-h-96 overflow-auto rounded-md border bg-background p-3 text-xs leading-relaxed text-foreground" data-testid="host-operator-contract-json">{formatHostOperatorContract(contractQuery.data)}</pre>
          )}
        </div>
      )}
    </section>
  );
}

export function MigHostOperators({ defaultOpen = false }: { defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <Card className="max-w-4xl border-primary/15 shadow-sm" data-testid="mig-host-operators">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <span className="mt-0.5 rounded-md bg-primary/10 p-2 text-primary"><KeyRound className="h-5 w-5" /></span>
            <div>
              <CardTitle className="text-base">Host-operator registration</CardTitle>
              <CardDescription className="mt-1 max-w-2xl">A separate, request-based identity review for operators that need it. Simple MIG discovery is unchanged.</CardDescription>
            </div>
          </div>
          <Button variant="ghost" size="sm" className="shrink-0" onClick={() => setOpen((value) => !value)} aria-expanded={open} data-testid="host-operator-section-toggle">
            {open ? "Collapse" : "Status"} <ChevronDown className={`ml-2 h-4 w-4 transition-transform ${open ? "rotate-180" : ""}`} />
          </Button>
        </div>
        {!open && <div className="mt-2 flex flex-wrap gap-2 pl-12" data-testid="host-operator-compact-summary">
          <StateBadge>smartdev-host-operator-dev</StateBadge><StateBadge>smartdev-bc-dev · BC / DEV</StateBadge><StateBadge>codex.version</StateBadge>
        </div>}
      </CardHeader>
      {open && (
        <CardContent className="space-y-4">
          <div className="grid gap-3 rounded-lg border border-primary/15 bg-primary/[0.035] p-4 text-sm sm:grid-cols-[1.2fr_1fr]">
            <div>
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Dedicated SmartDev identity</p>
              <p className="mt-2 break-all font-mono text-xs font-semibold">smartdev-host-operator-dev</p>
              <p className="mt-1 break-all font-mono text-xs text-muted-foreground">Client: smartdev-bc-dev</p>
            </div>
            <div className="sm:border-l sm:pl-4">
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Initial boundary</p>
              <p className="mt-2">Project <span className="font-semibold">BC</span> · Environment <span className="font-semibold">DEV</span></p>
              <p className="mt-1 font-mono text-xs">Capability: codex.version</p>
            </div>
            <p className="sm:col-span-2 flex items-start gap-2 border-t border-primary/10 pt-3 text-xs text-muted-foreground">
              <Clipboard className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              The requester automation creates a challenge, signs its exact payload with a dedicated Ed25519 key, and submits the public key. Keep private keys external. Key possession, discovery, registration, or approval alone does not verify SmartDev enrollment or authorize execution.
            </p>
          </div>
          <HostOperatorRequestList />
          <AutomationContract />
          <p className="text-xs text-muted-foreground">
            An independent administrator reviews each request through the provided decision API. This surface is status-only: it does not collect validation evidence or make approval decisions.
          </p>
        </CardContent>
      )}
    </Card>
  );
}
