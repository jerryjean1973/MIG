import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { fetchWithAuth } from "@/lib/queryClient";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SimpleMigConnect } from "./mig-simple-connect";

type DnsResult = {
  zone: string;
  queries: { name: string; status: string; error?: string }[];
  services: { record: string; hostname: string; port: number; origin: string; priority: number; weight: number }[];
  sitemaps?: {
    documents: { url: string; status: string; error?: string }[];
    urls: { url: string; sitemap: string }[];
    limited: boolean; max_sitemaps: number; max_urls: number;
  };
};
async function json<T>(path: string, body?: unknown): Promise<T> {
  const response = await fetchWithAuth(path, body === undefined ? undefined : {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(await response.text() || "DNS discovery failed.");
  return response.json();
}

export function MigDnsDiscovery({ onConnected }: { onConnected: () => void }) {
  const [zoneOverride, setZoneOverride] = useState<string | null>(null);
  const [endpoint, setEndpoint] = useState<string | null>(null);
  const [urlFilter, setUrlFilter] = useState("");
  const [visibleUrls, setVisibleUrls] = useState(100);
  const defaults = useQuery({
    queryKey: ["/api/mig/admin/onboarding/dns-default"],
    queryFn: () => json<{ zone: string; source: string; approved_public_zones?: string[] }>("/api/mig/admin/onboarding/dns-default"),
  });
  const zone = zoneOverride ?? defaults.data?.zone ?? "";
  const discovery = useMutation({
    mutationFn: (requestedZone: string) => json<DnsResult>("/api/mig/admin/onboarding/discover-dns", { zone: requestedZone }),
  });
  const sitemapUrls = (discovery.data?.sitemaps?.urls ?? []).filter(item => item.url.toLowerCase().includes(urlFilter.toLowerCase()));
  return <div className="space-y-4">
    <div className="space-y-2">
      <Label htmlFor="mig-dns-zone">Organization domain or alternate private zone</Label>
      <Input id="mig-dns-zone" value={zone} disabled={discovery.isPending}
        placeholder="bcentrisk.com"
        onChange={event => { setZoneOverride(event.target.value); discovery.reset(); setEndpoint(null); }} />
      <p className="text-xs text-muted-foreground">Uses the organization’s saved domain by default. You can enter an alternate private DNS zone. Private zones must be resolvable by this server.</p>
      {defaults.data?.source === "platform_default" && <p className="text-xs text-muted-foreground">Using the platform default, bcentrisk.com. Private organizations can replace it with their own domain or private zone.</p>}
    </div>
    {!!defaults.data?.approved_public_zones?.length && <section className="space-y-2" aria-label="Approved public DNS zones">
      <p className="text-sm font-medium">Approved public DNS zones</p>
      <div className="flex flex-wrap gap-2">
        {defaults.data.approved_public_zones.map(approvedZone => <Button key={approvedZone} type="button" size="sm"
          variant={zone === approvedZone ? "default" : "outline"} disabled={discovery.isPending}
          aria-pressed={zone === approvedZone}
          onClick={() => { setZoneOverride(approvedZone); discovery.reset(); setEndpoint(null); }}>
          {approvedZone}
        </Button>)}
      </div>
      <p className="text-xs text-muted-foreground">Approved for domain discovery, including public sitemap reads. This does not grant client access or widen approved network scopes.</p>
    </section>}
    {defaults.error && <p role="alert" className="text-sm text-destructive">Could not load the organization domain. Enter a zone manually.</p>}
    <Button disabled={!zone.trim() || discovery.isPending} onClick={() => { setEndpoint(null); setUrlFilter(""); setVisibleUrls(100); discovery.mutate(zone.trim()); }}>
      {discovery.isPending ? "Checking DNS and sitemaps…" : "Discover domain"}
    </Button>
    <p className="text-xs text-muted-foreground">Checks SRV advertisements plus robots.txt, sitemap.xml and linked sitemap indexes—even without service DNS records. Only the selected HTTPS origin is read; no MCP tools are invoked or clients registered. Private website reads require existing approved network scopes.</p>
    {discovery.error && <p role="alert" className="text-sm text-destructive">{discovery.error.message}</p>}
    {discovery.data && <section className="space-y-3 rounded-md border p-3" aria-label="DNS discovery results">
      <h3 className="text-sm font-medium">DNS results for {discovery.data.zone}</h3>
      {discovery.data.queries.map(query => <p key={query.name} className="break-all text-xs text-muted-foreground">{query.name}: {query.status === "no_records" ? "No SRV records" : query.status}{query.error && query.status === "error" ? ` (${query.error})` : ""}</p>)}
      {!discovery.data.services.length && <p className="text-sm">No MCP SRV advertisements were found. Sitemap findings are shown separately; missing SRV records do not prove there are no clients.</p>}
      {discovery.data.services.map((service, index) => <div key={`${service.record}-${index}`} className="space-y-2 rounded-md border p-3">
        <p className="break-all text-sm font-medium">{service.hostname}:{service.port}</p>
        <p className="text-xs text-muted-foreground">Priority {service.priority} · weight {service.weight} · DNS advertisement only, identity unverified</p>
        <Button variant="outline" size="sm" onClick={() => setEndpoint(service.origin)}>Inspect endpoint</Button>
      </div>)}
      {discovery.data.sitemaps && <section className="space-y-3 border-t pt-3" aria-label="Sitemap discovery results">
        <h4 className="text-sm font-medium">Sitemap URLs · {discovery.data.sitemaps.urls.length}</h4>
        <p className="text-xs text-muted-foreground">These are exact URLs listed by the website, not verified MCP endpoints. Each retains its source sitemap.</p>
        {discovery.data.sitemaps.documents.map((document, index) => <p key={`${document.url}-${index}`} className="break-all text-xs text-muted-foreground">{document.url}: {document.status}{document.error ? ` (${document.error})` : ""}</p>)}
        {discovery.data.sitemaps.limited && <p role="status" className="text-xs text-amber-600">Partial inventory: the scan limit was reached ({discovery.data.sitemaps.max_sitemaps} sitemaps / {discovery.data.sitemaps.max_urls} URLs).</p>}
        {!discovery.data.sitemaps.urls.length ? <p className="text-sm">No sitemap URLs were retrieved. Read errors or absent listings do not establish that no MCP endpoints exist.</p> : <>
          <Label htmlFor="mig-sitemap-filter">Filter sitemap URLs</Label>
          <Input id="mig-sitemap-filter" value={urlFilter} onChange={event => { setUrlFilter(event.target.value); setVisibleUrls(100); }} placeholder="Search listed URLs" />
          <p className="text-xs text-muted-foreground">{sitemapUrls.length} matching URLs</p>
          <div className="max-h-96 space-y-2 overflow-y-auto">
            {sitemapUrls.slice(0, visibleUrls).map(item => <div key={item.url} className="space-y-2 rounded-md border p-3">
              <p className="break-all text-sm">{item.url}</p>
              <p className="break-all text-xs text-muted-foreground">Source: {item.sitemap}</p>
              <Button size="sm" variant="outline" onClick={() => setEndpoint(item.url)}>Inspect endpoint</Button>
            </div>)}
          </div>
          {sitemapUrls.length > visibleUrls && <Button size="sm" variant="outline" onClick={() => setVisibleUrls(count => count + 100)}>Show more URLs</Button>}
        </>}
      </section>}
    </section>}
    {endpoint && <div className="space-y-3 border-t pt-4">
      <p className="text-sm text-muted-foreground">Confirm the exact HTTPS MCP endpoint below before testing. Sitemap URLs are unverified; SRV records provide no MCP path. Existing connection and private-network guards still apply.</p>
      <SimpleMigConnect key={endpoint} initialEndpoint={endpoint} onConnected={onConnected} />
    </div>}
  </div>;
}
