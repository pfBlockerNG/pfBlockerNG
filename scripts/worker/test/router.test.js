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
