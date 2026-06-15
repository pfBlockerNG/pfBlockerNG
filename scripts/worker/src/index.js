// Cloudflare Worker — pfBlockerNG pkg routing (ADR-20).
//
// A pfSense box's pkg(8) hits this Worker (its repo-conf url is the Worker, not
// Pages directly). The Worker reads the request's User-Agent, matches it against
// routing.json (fetched from Pages, edge-cached 5 min), and 302-redirects to the
// matrix-projected catalog dir on Pages:
//
//   <channel>/<varver>/<arch>/<rest>
//
// where
//   channel = "nightly" when the request path starts with /nightly/, else "release"
//             (the nightly repo-conf url carries a /nightly/ prefix; the release
//             repo-conf url does not — see scripts/add-repo.sh);
//   varver  = the catalog matched from the UA via routing.json (first match wins),
//             e.g. "ce-2.8" / "plus-26.03";
//   arch    = the architecture parsed from the request's FreeBSD:<major>:<arch>
//             ABI segment (amd64 / aarch64) — the catalog leaf is the bare arch,
//             since the varver segment already implies the FreeBSD major;
//   rest    = the path AFTER the ABI segment (meta.conf, packagesite.pkg,
//             <name>-<version>.pkg, ...).
//
// This mirrors the tree scripts/build-repo-portable.py --build-matrix lays out.
//
// Failure modes are explicit, never a silent wrong install:
//   - routing.json unavailable                         → 502
//   - no route matches the UA (unsupported version)    → 404
//   - the request path carries no valid ABI segment    → 404

const PAGES_BASE = "https://pfblockerng.github.io/pkg";
const ROUTING_MANIFEST_URL = `${PAGES_BASE}/routing.json`;
const CACHE_TTL = 300; // seconds — edge cache for routing.json

// Parse the architecture out of a FreeBSD ABI segment.
//   "FreeBSD:15:amd64"   -> "amd64"
//   "FreeBSD:16:aarch64" -> "aarch64"
// Anything that is not a well-formed ABI segment -> null (caller 404s).
export function parseArch(abiSegment) {
  const m = /^FreeBSD:\d+:([A-Za-z0-9_]+)$/.exec(abiSegment ?? "");
  return m ? m[1] : null;
}

// Normalize the parsed routing.json to a routes array, or null when the manifest
// has an unexpected shape — so a malformed manifest fails closed (502) instead of
// throwing past the explicit error handling on routes.find().
export function normalizeRoutes(data) {
  return Array.isArray(data?.routes) ? data.routes : null;
}

// Resolve the Pages target URL for a request path + matched route.
// Returns the absolute Pages URL, or null when the path has no valid ABI segment.
export function resolveTarget(pathname, route) {
  const segments = pathname.split("/").filter((s) => s.length > 0);

  // A leading /nightly/ selects the nightly channel tree; otherwise release.
  let channel = "release";
  if (segments[0] === "nightly") {
    channel = "nightly";
    segments.shift();
  }

  // The next segment must be the FreeBSD ABI (the repo-conf url is "<worker>/${ABI}").
  const arch = parseArch(segments.shift());
  if (!arch) {
    return null;
  }

  const rest = segments.join("/");
  return `${PAGES_BASE}/${channel}/${route.catalog}/${arch}/${rest}`;
}

export default {
  async fetch(request, env, ctx) {
    const ua = request.headers.get("User-Agent") ?? "";
    const url = new URL(request.url);

    const routes = await getRoutes(ctx);
    if (!routes) {
      return new Response("Routing manifest unavailable", { status: 502 });
    }

    // First match wins; routing.json lists more-specific patterns first
    // (e.g. "Netgate pfSense Plus/26.03" before "pfSense/2.8").
    const route = routes.find((r) => ua.includes(r.pattern));
    if (!route) {
      return new Response(`Unsupported pfSense version (UA: ${ua})`, { status: 404 });
    }

    const target = resolveTarget(url.pathname, route);
    if (!target) {
      return new Response(`Malformed request path (expected an ABI segment): ${url.pathname}`, {
        status: 404,
      });
    }
    return Response.redirect(target, 302);
  },
};

async function getRoutes(ctx) {
  const cache = caches.default;
  const cacheKey = new Request(ROUTING_MANIFEST_URL);
  let resp = await cache.match(cacheKey);
  if (!resp) {
    resp = await fetch(ROUTING_MANIFEST_URL);
    if (!resp.ok) return null;
    const ttlResp = new Response(resp.body, resp);
    ttlResp.headers.set("Cache-Control", `s-maxage=${CACHE_TTL}`);
    ctx.waitUntil(cache.put(cacheKey, ttlResp.clone()));
    resp = ttlResp;
  }
  const data = await resp.clone().json();
  return normalizeRoutes(data);
}
