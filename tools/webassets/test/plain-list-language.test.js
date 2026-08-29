// Runtime test for pfbPlainListLanguage (issue #1875) -- proves plain-list mode really
// dropped the parseMixed regex overlay, not just that its export exists. If someone later
// wires mixedParser into pfbPlainListLanguage (e.g. copy-paste from pfbRegexListLanguage),
// this test goes red: the whole point of a plain-list mode is that a domain/TLD/IP entry
// like "bad(regex" is never handed to the Python-re grammar.
import { test } from "node:test";
import assert from "node:assert/strict";
import { pfbPlainListLanguage, pfbRegexListLanguage } from "../lezer-pfb-regex-list/src/index.js";

const input = "bad(regex\n# comment";

// tree.iterate() doesn't follow parseMixed overlay mounts (see
// lezer-pfb-regex-list/test/parse.test.js's chainAt() comment) -- resolveInner() walks
// position-based through the mount, which is what a real syntax-highlighting/lint consumer
// does too.
function chainAt(tree, pos) {
  const chain = [];
  let node = tree.resolveInner(pos, 1);
  while (node) {
    chain.push(node.name);
    node = node.parent;
  }
  return chain;
}

test("both languages split the same input into a top-level Pattern and Comment", () => {
  for (const language of [pfbPlainListLanguage, pfbRegexListLanguage]) {
    const names = [];
    language.parser.parse(input).iterate({
      enter(node) {
        names.push(node.name);
      },
    });
    assert.deepEqual(names, ["RegexList", "Pattern", "Comment"]);
  }
});

test("plain mode: a position inside the Pattern resolves directly to Pattern -- no mounted regex subtree", () => {
  const tree = pfbPlainListLanguage.parser.parse(input);
  for (const pos of [1, 2, 3, 5]) {
    assert.deepEqual(chainAt(tree, pos), ["Pattern", "RegexList"], `pos ${pos} must resolve to bare Pattern, no descendants`);
  }
});

test("mixed (regex-list) mode: the same positions resolve THROUGH a mounted RegExp subtree", () => {
  const tree = pfbRegexListLanguage.parser.parse(input);
  for (const pos of [1, 2, 3, 5]) {
    const chain = chainAt(tree, pos);
    assert.ok(chain.includes("RegExp"), `pos ${pos}: expected the chain to pass through a mounted RegExp node, got ${JSON.stringify(chain)}`);
    assert.ok(chain.includes("Pattern"), `pos ${pos}: expected the chain to still reach Pattern above the mount, got ${JSON.stringify(chain)}`);
    assert.notEqual(chain[0], "Pattern", `pos ${pos}: expected the innermost node to be a mounted descendant, not Pattern itself`);
  }
});
