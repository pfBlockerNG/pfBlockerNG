// Unit coverage for the pkg-routing Worker's pure path-mapping helpers (ADR-20).
// Run: node --test  (from scripts/worker/)  — no wrangler / network needed.
//
// These pin the request -> Pages target mapping against the tree
// build-repo-portable.py --build-matrix lays out: <channel>/<varver>/<arch>/<rest>.

import { test } from "node:test";
import assert from "node:assert/strict";

import worker, { normalizeRoutes, parseArch, resolveTarget } from "../src/index.js";

const PAGES = "https://pfblockerng.github.io/pkg";
const CE = { pattern: "pfSense/2.8", catalog: "ce-2.8", status: "active" };
const PLUS = { pattern: "Netgate pfSense Plus/26.03", catalog: "plus-26.03", status: "active" };

test("parseArch extracts the arch from a FreeBSD ABI segment", () => {
  assert.equal(parseArch("FreeBSD:15:amd64"), "amd64");
  assert.equal(parseArch("FreeBSD:16:aarch64"), "aarch64");
});

test("parseArch rejects non-ABI segments", () => {
  // The off branch: anything that is not FreeBSD:<digits>:<arch> -> null (caller 404s).
  assert.equal(parseArch("nightly"), null);
  assert.equal(parseArch("amd64"), null);
  assert.equal(parseArch(""), null);
  assert.equal(parseArch(undefined), null);
});

test("release request maps to the release/<varver>/<arch>/ tree", () => {
  // Given a CE release request (no channel prefix), the catalog file lands under release/.
  const target = resolveTarget("/FreeBSD:15:amd64/meta.conf", CE);
  assert.equal(target, `${PAGES}/release/ce-2.8/amd64/meta.conf`);
});

test("explicit /release/ prefix maps to the release tree (symmetric with /nightly/)", () => {
  // The client conf may carry an explicit /release/ prefix; it maps to the same release tree
  // as the bare path — the prefix segment is consumed, not treated as the ABI.
  const target = resolveTarget("/release/FreeBSD:15:amd64/meta.conf", CE);
  assert.equal(target, `${PAGES}/release/ce-2.8/amd64/meta.conf`);
});

test("explicit /release/ for Plus aarch64 maps correctly", () => {
  const target = resolveTarget("/release/FreeBSD:16:aarch64/packagesite.pkg", PLUS);
  assert.equal(target, `${PAGES}/release/plus-26.03/aarch64/packagesite.pkg`);
});

test("nightly request maps to the nightly/<varver>/<arch>/ tree", () => {
  // The /nightly/ prefix flips the channel dir; everything else is identical.
  // Before: the same path WITHOUT the prefix would be release/ (proven above);
  // here the prefix is the only change, so green proves the prefix drives the channel.
  const target = resolveTarget("/nightly/FreeBSD:15:amd64/meta.conf", CE);
  assert.equal(target, `${PAGES}/nightly/ce-2.8/amd64/meta.conf`);
});

test("Plus aarch64 request maps to its own arch leaf", () => {
  const target = resolveTarget("/FreeBSD:16:aarch64/packagesite.pkg", PLUS);
  assert.equal(target, `${PAGES}/release/plus-26.03/aarch64/packagesite.pkg`);
});

test("a package download path (after the ABI segment) is preserved verbatim", () => {
  const target = resolveTarget("/FreeBSD:15:amd64/pfBlockerNG-devel-3.2.16.pkg", CE);
  assert.equal(target, `${PAGES}/release/ce-2.8/amd64/pfBlockerNG-devel-3.2.16.pkg`);
});

test("normalizeRoutes returns the array for a well-formed manifest", () => {
  assert.deepEqual(normalizeRoutes({ routes: [CE] }), [CE]);
});

test("normalizeRoutes returns null for a malformed manifest (fail-closed 502 branch)", () => {
  // A non-array routes (or missing / non-object data) must NOT reach routes.find()
  // — returning null makes the Worker answer 502, never throw an unhandled 500.
  assert.equal(normalizeRoutes({ routes: { pattern: "x" } }), null);
  assert.equal(normalizeRoutes({}), null);
  assert.equal(normalizeRoutes(null), null);
  assert.equal(normalizeRoutes("nope"), null);
});

test("a request with no ABI segment resolves to null (the 404 branch)", () => {
  assert.equal(resolveTarget("/", CE), null);
  assert.equal(resolveTarget("/notanabi/meta.conf", CE), null);
  // A /nightly/ prefix followed by no ABI is still malformed.
  assert.equal(resolveTarget("/nightly/", CE), null);
});

test("bare base URL redirects a browser to the human landing page (not a 404)", async () => {
  // A browser hitting "/" has no pfSense UA — it must land on the Pages page, not 404.
  const res = await worker.fetch(new Request("https://pkg.pfblockerng.workers.dev/"), {}, { waitUntil() {} });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get("location"), `${PAGES}/`);
});

// --- worker.fetch UA dispatch (the route MATCH) ------------------------------
// The helpers above pin the path math (resolveTarget). These drive worker.fetch
// end-to-end to pin the OTHER half — matching the request's User-Agent against
// routing.json — which is the exact decision the live Worker makes and the one the
// ADR-20 Case-4 live-VM gate exercises. getRoutes() reads caches.default + global
// fetch, so we stub the edge to serve a known manifest WITHOUT any network.
const ROUTING_URL = `${PAGES}/routing.json`;
const CTX = { waitUntil() {} };

// Stub the edge so getRoutes() resolves `manifest` (a cache HIT serves it directly),
// or, when `manifest === null`, a cache MISS + a 5xx fetch (the fail-closed path).
function stubEdge(manifest) {
  globalThis.caches = {
    default: {
      async match() {
        return manifest === null ? undefined : new Response(JSON.stringify(manifest), { status: 200 });
      },
      async put() {},
    },
  };
  // Only reached on a cache miss (the manifest === null / 502 path).
  globalThis.fetch = async (url) => {
    assert.equal(String(url), ROUTING_URL, "getRoutes must fetch the Pages routing.json");
    return new Response("unavailable", { status: 500 });
  };
}

function route(ua, path) {
  const headers = ua === null ? {} : { "User-Agent": ua };
  return worker.fetch(new Request(`https://pkg.pfblockerng.workers.dev${path}`, { headers }), {}, CTX);
}

// routing.json lists the more-specific pattern (Plus) first, exactly as published.
const MANIFEST = { routes: [PLUS, CE] };

test("fetch: a CE pfSense UA is routed to the ce-2.8 release catalog", async () => {
  stubEdge(MANIFEST);
  const res = await route("pkg/1.21 (FreeBSD:15:amd64; pfSense/2.8)", "/FreeBSD:15:amd64/meta.conf");
  assert.equal(res.status, 302);
  assert.equal(res.headers.get("location"), `${PAGES}/release/ce-2.8/amd64/meta.conf`);
});

test("fetch: a Plus pfSense UA is routed to the plus-26.03 release catalog", async () => {
  // Same request shape, different UA -> different catalog: proves the UA (not the path)
  // drives the variant. aarch64 also confirms the arch leaf rides through.
  stubEdge(MANIFEST);
  const res = await route("pkg/1.21 (FreeBSD:16:aarch64; Netgate pfSense Plus/26.03)", "/FreeBSD:16:aarch64/packagesite.pkg");
  assert.equal(res.status, 302);
  assert.equal(res.headers.get("location"), `${PAGES}/release/plus-26.03/aarch64/packagesite.pkg`);
});

test("fetch: a /nightly/ path with a CE UA hits the nightly ce-2.8 tree", async () => {
  // The UA picks the variant; the /nightly/ prefix picks the channel — both compose.
  stubEdge(MANIFEST);
  const res = await route("pkg/1.21 (FreeBSD:15:amd64; pfSense/2.8)", "/nightly/FreeBSD:15:amd64/meta.conf");
  assert.equal(res.status, 302);
  assert.equal(res.headers.get("location"), `${PAGES}/nightly/ce-2.8/amd64/meta.conf`);
});

test("fetch: a non-pfSense UA matches no route -> 404 (never a wrong-variant install)", async () => {
  // The whole point of UA routing: a client whose UA matches no pattern is refused,
  // not silently served some default catalog.
  stubEdge(MANIFEST);
  for (const ua of ["curl/8.7.1", "pkg/1.21.3", null]) {
    const res = await route(ua, "/FreeBSD:15:amd64/meta.conf");
    assert.equal(res.status, 404, `UA ${JSON.stringify(ua)} should 404`);
  }
});

test("fetch: first matching route wins (routing.json order is honored)", async () => {
  // Two patterns both substrings of the UA -> find() returns the FIRST. Pins that the
  // published "more-specific first" ordering is what selects the catalog.
  stubEdge({
    routes: [
      { pattern: "pfSense/2.8", catalog: "ce-2.8", status: "active" },
      { pattern: "pfSense", catalog: "generic", status: "active" },
    ],
  });
  const res = await route("pkg/1.21 (FreeBSD:15:amd64; pfSense/2.8)", "/FreeBSD:15:amd64/meta.conf");
  assert.equal(res.headers.get("location"), `${PAGES}/release/ce-2.8/amd64/meta.conf`);
});

test("fetch: a matched UA with no ABI segment in the path -> 404", async () => {
  // The UA resolves, but the path carries no FreeBSD:<major>:<arch> segment -> the
  // resolveTarget null branch surfaces as a 404 (not a 302 to a malformed target).
  stubEdge(MANIFEST);
  const res = await route("pkg/1.21 (FreeBSD:15:amd64; pfSense/2.8)", "/notanabi/meta.conf");
  assert.equal(res.status, 404);
});

test("fetch: routing.json unavailable -> 502 (fail closed, never a guess)", async () => {
  // Cache miss + a 5xx manifest fetch: getRoutes returns null and the Worker answers
  // 502 rather than throwing or defaulting to some catalog.
  stubEdge(null);
  const res = await route("pkg/1.21 (FreeBSD:15:amd64; pfSense/2.8)", "/FreeBSD:15:amd64/meta.conf");
  assert.equal(res.status, 502);
});

// --- route-only (EOL) version routing (ADR-27 §2.4) -------------------------
// A route-only version is a routing.json entry for an EOL pfSense version whose
// .pkg is served from a frozen release/<varver>/ catalog — identical structure to
// a live build entry. The Worker sees the same {pattern, catalog, status} shape and
// routes it the same way; no code change in index.js is needed or made (ADR-27 §2.4:
// "Worker unchanged"). These tests guard that invariant.

// Manifest with live build entries + route-only (EOL) entries alongside them,
// mirroring how routing.json carries all served versions in production.
const CE_EOL = { pattern: "pfSense/2.6", catalog: "ce-2.6", status: "EOL" };
const PLUS_EOL = { pattern: "Netgate pfSense Plus/25.03", catalog: "plus-25.03", status: "EOL" };
// More-specific (Plus) patterns first; EOL entries listed after active ones, matching
// the published order — but UA matching is pattern-substring, so order within EOL does
// not matter; the guard cases below pin that CE and Plus patterns never cross-match.
const MANIFEST_WITH_EOL = { routes: [PLUS, CE, PLUS_EOL, CE_EOL] };

test("fetch: route-only CE version (pfSense/2.6) routes to release/ce-2.6/ — not 404", async () => {
  // Given a routing.json that includes a route-only CE entry alongside live entries:
  // When a pfSense 2.6 CE box requests a file,
  // Then the Worker 302-redirects to the frozen release/ce-2.6/ catalog — routed normally,
  // NOT 404'd. Proves a route-only route is an ordinary entry; no special-casing needed.
  stubEdge(MANIFEST_WITH_EOL);
  const res = await route(
    "pkg/1.21 (FreeBSD:14:amd64; pfSense/2.6)",
    "/FreeBSD:14:amd64/packagesite.pkg",
  );
  assert.equal(res.status, 302, "EOL CE version must be routed, not rejected");
  assert.equal(
    res.headers.get("location"),
    `${PAGES}/release/ce-2.6/amd64/packagesite.pkg`,
    "EOL CE must map to release/ce-2.6/ (normal path, not a special archive path)",
  );
});

test("fetch: route-only Plus version (pfSense Plus/25.03) routes to release/plus-25.03/ — not 404", async () => {
  // Given a routing.json with a route-only Plus entry alongside live entries:
  // When a pfSense Plus 25.03 box requests a file,
  // Then the Worker 302-redirects to the frozen release/plus-25.03/ catalog — not 404.
  // The status field is "EOL" but the Worker does not consult it (informational only).
  stubEdge(MANIFEST_WITH_EOL);
  const res = await route(
    "pkg/1.21 (FreeBSD:15:aarch64; Netgate pfSense Plus/25.03)",
    "/FreeBSD:15:aarch64/meta.conf",
  );
  assert.equal(res.status, 302, "EOL Plus version must be routed, not rejected");
  assert.equal(
    res.headers.get("location"),
    `${PAGES}/release/plus-25.03/aarch64/meta.conf`,
    "EOL Plus must map to release/plus-25.03/ (normal path, not a special archive path)",
  );
});

test("fetch: route-only CE UA does NOT match the Plus route-only pattern (opposite-edition guard)", async () => {
  // Before: the CE-EOL UA resolves to ce-2.6 (proven above).
  // Here: a manifest with ONLY the Plus-EOL route confirms the CE-EOL UA gets 404,
  // proving the CE pattern "pfSense/2.6" and the Plus pattern "Netgate pfSense Plus/25.03"
  // never cross-match — the UA substring "pfSense/2.6" does NOT appear in "Netgate pfSense Plus/25.03".
  stubEdge({ routes: [PLUS_EOL] });
  const res = await route(
    "pkg/1.21 (FreeBSD:14:amd64; pfSense/2.6)",
    "/FreeBSD:14:amd64/meta.conf",
  );
  assert.equal(res.status, 404, "CE-EOL UA must not match the Plus-EOL route");
});

test("fetch: route-only Plus UA does NOT match the CE route-only pattern (opposite-edition guard)", async () => {
  // Mirror of the above: a manifest with ONLY the CE-EOL route confirms the Plus-EOL UA
  // gets 404 — "Netgate pfSense Plus/25.03" does NOT contain "pfSense/2.6".
  // Together these two guards pin that EOL entries share no cross-edition pattern leakage.
  stubEdge({ routes: [CE_EOL] });
  const res = await route(
    "pkg/1.21 (FreeBSD:15:aarch64; Netgate pfSense Plus/25.03)",
    "/FreeBSD:15:aarch64/meta.conf",
  );
  assert.equal(res.status, 404, "Plus-EOL UA must not match the CE-EOL route");
});
