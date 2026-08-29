// styleTags mapping for the pfb regex-list outer grammar (issue #1669 slice B).
// Pattern carries no tag of its own -- its highlighting comes entirely from the mounted
// Python-re grammar's tree (parseMixed, see index.js).
import { styleTags, tags as t } from "@lezer/highlight";

export const pfbRegexListHighlighting = styleTags({
  Comment: t.lineComment,
});
