// Unit coverage for the pkg-routing Worker's pure path-mapping helpers (ADR-20).
// Run: node --test  (from scripts/worker/)  — no wrangler / network needed.
//
// These pin the request -> Pages target mapping against the tree
// build-repo-portable.py --build-matrix lays out: <channel>/<varver>/<arch>/<rest>.

import { test } from "node:test";
import assert from "node:assert/strict";

import { parseArch, resolveTarget } from "../src/index.js";

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

test("a request with no ABI segment resolves to null (the 404 branch)", () => {
  assert.equal(resolveTarget("/", CE), null);
  assert.equal(resolveTarget("/notanabi/meta.conf", CE), null);
  // A /nightly/ prefix followed by no ABI is still malformed.
  assert.equal(resolveTarget("/nightly/", CE), null);
});
