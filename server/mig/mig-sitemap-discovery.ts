import { SaxesParser } from "saxes";
import { fetchMigDiscoveryDocument } from "./mig-registry-network";

const MAX_SITEMAPS = 6;
const MAX_URLS = 1000;
type DocumentRead = (url: string, scopes: string[]) => Promise<string>;

/** Parse source syntax only. No URL is semantically classified as an MCP service. */
export function parseMigSitemap(xml: string): { index: boolean; locations: string[]; limited: boolean } {
  const parser = new SaxesParser({ xmlns: true });
  const stack: string[] = [];
  const locations: string[] = [];
  let index = false;
  let rootSeen = false;
  let text = "";
  let limited = false;
  parser.on("doctype", () => { throw new Error("MIG_SITEMAP_DOCTYPE_FORBIDDEN"); });
  parser.on("opentag", tag => {
    stack.push(tag.local);
    if (stack.length === 1) {
      rootSeen = true;
      if (!["sitemapindex", "urlset"].includes(tag.local)) throw new Error("MIG_SITEMAP_ROOT_INVALID");
      index = tag.local === "sitemapindex";
    }
    if (tag.local === "loc") text = "";
  });
  const append = (value: string) => { if (stack.at(-1) === "loc") text += value; };
  parser.on("text", append);
  parser.on("cdata", append);
  parser.on("closetag", tag => {
    if (tag.local === "loc" && stack.length === 3 && stack[1] === (index ? "sitemap" : "url")) {
      if (locations.length < MAX_URLS) locations.push(text.trim());
      else limited = true;
    }
    stack.pop();
  });
  parser.write(xml).close();
  if (!rootSeen) throw new Error("MIG_SITEMAP_EMPTY");
  return { index, locations, limited };
}

export async function discoverMigSitemapUrls(
  zone: string, privateScopes: string[] = [], read: DocumentRead = fetchMigDiscoveryDocument,
) {
  const origin = `https://${zone}`;
  const documents: { url: string; status: string; error?: string }[] = [];
  const urls = new Map<string, { url: string; sitemap: string }>();
  const queue = [`${origin}/sitemap.xml`];
  const visited = new Set<string>();
  let limited = false;
  const scopedUrl = (value: string, base: string) => {
    if (!value.trim()) throw new Error("MIG_SITEMAP_LOCATION_EMPTY");
    const parsed = new URL(value, base);
    if (parsed.origin !== origin || parsed.username || parsed.password || parsed.hash || parsed.href.length > 2048) {
      throw new Error("MIG_SITEMAP_OUTSIDE_SELECTED_ORIGIN");
    }
    return parsed.href;
  };
  const recordError = (url: string, error: unknown) => documents.push({
    url, status: "error", error: error instanceof Error ? error.message : "MIG_SITEMAP_READ_FAILED",
  });
  const robots = `${origin}/robots.txt`;
  try {
    const text = await read(robots, privateScopes);
    documents.push({ url: robots, status: "read" });
    for (const line of text.split(/\r?\n/)) {
      const match = /^\s*sitemap\s*:\s*(\S+)\s*(?:#.*)?$/i.exec(line);
      if (!match) continue;
      try {
        const url = scopedUrl(match[1], robots);
        if (queue.length < MAX_SITEMAPS) queue.push(url); else limited = true;
      } catch (error) { recordError(robots, error); }
    }
  } catch (error) { recordError(robots, error); }
  while (queue.length && visited.size < MAX_SITEMAPS && urls.size < MAX_URLS) {
    const batch = [...new Set(queue.splice(0, 3))].filter(url => !visited.has(url)).slice(0, MAX_SITEMAPS - visited.size);
    for (const url of batch) visited.add(url);
    await Promise.all(batch.map(async sitemap => {
      try {
        const parsed = parseMigSitemap(await read(sitemap, privateScopes));
        limited ||= parsed.limited;
        documents.push({ url: sitemap, status: "read" });
        for (const location of parsed.locations) {
          let url: string;
          try { url = scopedUrl(location, sitemap); }
          catch (error) { if (!documents.some(row => row.url === sitemap && row.error === "MIG_SITEMAP_OUTSIDE_SELECTED_ORIGIN")) recordError(sitemap, error); continue; }
          if (parsed.index) {
            if (!visited.has(url) && !queue.includes(url)) {
              if (queue.length + visited.size < MAX_SITEMAPS) queue.push(url); else limited = true;
            }
          } else if (urls.size < MAX_URLS) urls.set(url, { url, sitemap });
          else limited = true;
        }
      } catch (error) { recordError(sitemap, error); }
    }));
  }
  return {
    documents, urls: [...urls.values()], limited: limited || queue.length > 0,
    max_sitemaps: MAX_SITEMAPS, max_urls: MAX_URLS,
    scope: "Same HTTPS origin only. Sitemap URLs are unverified, not confirmed MCP endpoints.",
  };
}
