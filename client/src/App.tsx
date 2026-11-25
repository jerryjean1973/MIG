import { useEffect, useState } from "react";
import { QueryClientProvider, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, ArrowUpRight, LockKeyhole, RefreshCw } from "lucide-react";
import { Link, useLocation } from "wouter";
import MigAdminPage from "@/pages/mig-admin-page";
import { fetchWithAuth, queryClient } from "@/lib/queryClient";

type Session = {
  authenticated: boolean;
  user?: { id: string; tenantId: string; role: string };
};
type Health = {
  status: string;
  configured: { database: boolean; oidc: boolean; downstream: boolean };
};

function useHealth() {
  return useQuery<Health>({
    queryKey: ["/api/health"],
    queryFn: async () => {
      const response = await fetchWithAuth("/api/health");
      if (!response.ok) throw new Error(`${response.status}: ${response.statusText || "Health check failed"}`);
      return response.json();
    },
    staleTime: 30_000,
    retry: false,
  });
}

function useSession() {
  return useQuery<Session>({
    queryKey: ["/api/auth/session"],
    queryFn: async () => {
      const response = await fetchWithAuth("/api/auth/session");
      if (response.status === 401) return { authenticated: false };
      if (!response.ok) throw new Error(`${response.status}: ${response.statusText || "Session check failed"}`);
      return response.json();
    },
    staleTime: 15_000,
    retry: false,
  });
}

function Brand() {
  return (
    <div className="brand-lockup">
      <div className="brand-mark" aria-hidden="true">M·I</div>
      <div>
        <div className="brand-name">MIG</div>
        <div className="brand-caption">Intent gateway</div>
      </div>
    </div>
  );
}

function LoadingScreen() {
  return (
    <main className="auth-loading" aria-label="Checking your session">
      <section className="auth-loading-card">
        <Brand />
        <div className="skeleton" style={{ width: "48%", marginTop: 34 }} />
        <div className="skeleton" style={{ width: "82%", marginTop: 14 }} />
        <div className="skeleton" style={{ width: "67%", marginTop: 10 }} />
      </section>
    </main>
  );
}

function SignIn() {
  const health = useHealth();
  const session = useSession();
  const [, setLocation] = useLocation();

  useEffect(() => {
    if (session.data?.authenticated) setLocation("/mig");
  }, [session.data?.authenticated, setLocation]);

  if (session.isLoading || (session.isFetching && !session.data)) return <LoadingScreen />;

  const unavailable = health.isError;
  const oidcReady = health.data?.configured.oidc === true;
  const databaseReady = health.data?.configured.database === true;
  const downstreamReady = health.data?.configured.downstream === true;
  const configReady = oidcReady && databaseReady && downstreamReady;

  return (
    <main className="auth-stage">
      <section className="auth-layout" aria-label="MIG administrator sign in">
        <div className="auth-story">
          <Brand />
          <div className="story-copy">
            <div className="eyebrow">Authorization workspace</div>
            <h1>Intent is the boundary.</h1>
            <p>Register AI and MCP clients, constrain what they can request, and inspect the exact decisions that shape each execution.</p>
          </div>
          <div className="story-foot"><span className="story-pip" />Tenant-aware administration · evidence-led decisions</div>
        </div>
        <div className="auth-panel">
          <div className="auth-kicker">Administrator access</div>
          <h2>Sign in to MIG</h2>
          <p className="auth-intro">Continue through your organization’s identity provider. MIG does not create or store separate passwords.</p>
          {unavailable && (
            <div className="auth-error" role="alert">
              The service status could not be reached. Sign-in availability cannot be confirmed. Retry the status check before continuing.
            </div>
          )}
          {health.data && (!databaseReady || !oidcReady || !downstreamReady) && (
            <div className="auth-error" role="status">
              <strong>Configuration is incomplete.</strong> {!databaseReady && "Database is not configured. "}
              {!oidcReady && "OIDC sign-in is not configured. "}
              {!downstreamReady && "The downstream authorization service is not configured. "}
              Access remains unavailable until the service is configured.
            </div>
          )}
          {session.isError && (
            <div className="auth-error" role="alert">
              Could not verify the current session. {session.error instanceof Error ? session.error.message : "Please retry."}
            </div>
          )}
          <button
            className="auth-action"
            type="button"
            disabled={!configReady || health.isLoading || unavailable}
            onClick={() => window.location.assign("/api/auth/login")}
          >
            <LockKeyhole size={16} strokeWidth={1.8} />
            Continue with organization sign-in
            <ArrowUpRight size={15} />
          </button>
          <div className="auth-divider">Service readiness</div>
          <div className="auth-note">
            <Activity size={15} aria-hidden="true" />
            <span>
              <strong>{health.data?.status ?? (health.isLoading ? "Checking service status" : "Status unavailable")}</strong>
              <br />Database {health.data ? (databaseReady ? "ready" : "not configured") : "—"} · OIDC {health.data ? (oidcReady ? "ready" : "not configured") : "—"} · Downstream {health.data ? (downstreamReady ? "ready" : "not configured") : "—"}
            </span>
          </div>
          <div className="auth-status">
            {health.isLoading ? "Checking /api/health…" : health.isError ? (
              <button className="text-action" type="button" onClick={() => health.refetch()}><RefreshCw size={12} /> Retry status check</button>
            ) : "Authentication is managed by your organization."}
          </div>
          <p className="auth-footnote">Access is scoped to the tenant and role assigned to your authenticated session. No client-side tenant selection is used.</p>
        </div>
      </section>
    </main>
  );
}

function MigShell() {
  const [, setLocation] = useLocation();
  const client = useQueryClient();
  const session = useSession();
  const [logoutError, setLogoutError] = useState("");
  useEffect(() => {
    if (!session.isLoading && (session.isError || !session.data?.authenticated)) setLocation("/");
  }, [session.data?.authenticated, session.isError, session.isLoading, setLocation]);
  const logout = useMutation({
    mutationFn: async () => {
      const response = await fetchWithAuth("/api/auth/logout", { method: "POST" });
      if (!response.ok) {
        const details = (await response.text().catch(() => "")) || response.statusText;
        throw new Error(`${response.status}: ${details || "Sign out was not acknowledged"}`);
      }
    },
    onSuccess: () => {
      client.clear();
      setLogoutError("");
      setLocation("/");
    },
    onError: (error) => setLogoutError(error instanceof Error ? error.message : "Sign out failed. Your session remains active."),
  });

  if (session.isLoading || session.isError || !session.data?.authenticated) return <LoadingScreen />;

  return (
    <div className="standalone-root">
      <header className="mig-shell-header">
        <Link href="/mig" className="mig-shell-brand" aria-label="MIG administration">
          <div className="brand-mark" aria-hidden="true">M·I</div>
          <span className="brand-name">MIG</span>
        </Link>
        <div className="mig-shell-user">
          <div className="mig-shell-identity">
            <div className="mig-shell-tenant">Tenant · {session.data.user?.tenantId ?? "session assigned"}</div>
            <div className="mig-shell-role">{session.data.user?.role ?? "Administrator"}</div>
          </div>
          <button className="mig-shell-logout" type="button" onClick={() => logout.mutate()} disabled={logout.isPending}>
            {logout.isPending ? "Signing out…" : "Sign out"}
          </button>
        </div>
      </header>
      {logoutError && <div className="mig-shell-error" role="alert">Sign out was not confirmed. {logoutError}</div>}
      <MigAdminPage />
    </div>
  );
}

function AppRoutes() {
  const [location, setLocation] = useLocation();
  const client = useQueryClient();

  useEffect(() => {
    const handleUnauthorized = () => {
      client.clear();
      setLocation("/");
    };
    window.addEventListener("mig:unauthorized", handleUnauthorized);
    return () => window.removeEventListener("mig:unauthorized", handleUnauthorized);
  }, [client, setLocation]);

  if (location === "/mig") return <MigShell />;
  return <SignIn />;
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AppRoutes />
    </QueryClientProvider>
  );
}

export default App;
