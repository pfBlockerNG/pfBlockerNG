// Cloudflare Worker — pfBlockerNG pkg routing (ADR-20 Phase 5).
//
// Reads User-Agent, fetches routing.json from Pages (edge-cached 5 min),
// matches the UA against route patterns (first match wins), and 302-redirects
// to the version-keyed catalog dir on Pages.
//
// Failure modes are explicit, never a silent wrong install:
//   - routing.json unavailable  → 502
//   - no matching route (unsupported pfSense version) → 404

const ROUTING_MANIFEST_URL = "https://pfblockerng.github.io/pkg/routing.json";
const CACHE_TTL = 300; // seconds — edge cache for routing.json

export default {
  async fetch(request, env, ctx) {
    const ua = request.headers.get("User-Agent") ?? "";
    const url = new URL(request.url);

    const routes = await getRoutes(ctx);
    if (!routes) {
      return new Response("Routing manifest unavailable", { status: 502 });
    }

    // First match wins; list more-specific patterns before less-specific ones
    // in routing.json (e.g. "pfSense/2.9" before a "pfSense/2" catch-all).
    const route = routes.find((r) => ua.includes(r.pattern));
    if (!route) {
      return new Response(`Unsupported pfSense version (UA: ${ua})`, {
        status: 404,
      });
    }

    // 302 redirect to the version-keyed catalog dir on Pages.
    // Input path:  /FreeBSD:15:amd64/packagesite.yaml.pkg
    // Output path: https://pfblockerng.github.io/pkg/ce-2.8/FreeBSD:15:amd64/...
    const target = `https://pfblockerng.github.io/pkg/${route.catalog}${url.pathname}`;
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
    ctx.waitUntil(cache.put(cacheKey, ttlResp));
  }
  const data = await resp.clone().json();
  return data.routes ?? null;
}
