import { QueryClient, type QueryFunction } from "@tanstack/react-query";

function sameOriginUrl(url: string): string {
  const target = new URL(url, window.location.origin);
  if (target.origin !== window.location.origin) {
    throw new Error("MIG standalone only permits same-origin API requests.");
  }
  return target.pathname + target.search + target.hash;
}

export async function fetchWithAuth(url: string, options: RequestInit = {}): Promise<Response> {
  const path = sameOriginUrl(url);
  const headers = new Headers(options.headers);
  // Tenant context comes from the authenticated server session, never a guessed client header.
  headers.delete("x-tenant-id");
  headers.delete("authorization");
  return fetch(path, {
    ...options,
    headers,
    credentials: "same-origin",
  });
}

async function responseError(response: Response): Promise<never> {
  const detail = (await response.text().catch(() => "")) || response.statusText || "Request failed";
  throw new Error(`${response.status}: ${detail}`);
}

export function getQueryFn<T>(): QueryFunction<T> {
  return async ({ queryKey, signal }) => {
    const queryUrl = queryKey.map(String).join("/");
    const response = await fetchWithAuth(queryUrl, { method: "GET", signal });
    if (response.status === 401) {
      window.dispatchEvent(new CustomEvent("mig:unauthorized"));
      return responseError(response);
    }
    if (!response.ok) return responseError(response);
    return response.json() as Promise<T>;
  };
}

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      queryFn: getQueryFn(),
      staleTime: 20_000,
      refetchOnWindowFocus: false,
      retry: false,
    },
    mutations: { retry: false },
  },
});
