#!/usr/bin/env python3
"""Standalone trigger for ``test_adr10_concurrency`` — run in a SEPARATE process.

It publishes a new DNSBL manifest and bumps the reload-generation sentinel exactly the
way PHP/shell do on a real box (stage → fsync → atomic ``rename``, then flip the
sentinel). Running it as its own process is the point: it shares NO GIL and NO module
state with the query process, so it genuinely exercises the atomic-publish-vs-
concurrent-read path. Pure stdlib — it deliberately does NOT import ``pfb_unbound``, so
it spawns clean under any start method.

argv: <wait_before_seconds> <new_manifest_src> <live_manifest_path> <sentinel_path>
"""

import os
import sys
import time


def _atomic_write(path: str, data: str) -> None:
    # Stage in the SAME dir, fsync, then rename — a concurrent reader sees the whole old
    # file or the whole new one, never a torn/partial manifest.
    tmp = "{}.tmp.{}".format(path, os.getpid())
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def main() -> int:
    wait_before = float(sys.argv[1])
    src = sys.argv[2]
    live_manifest = sys.argv[3]
    sentinel = sys.argv[4]

    # Let the query process take a handful of baseline queries against the OLD lists.
    time.sleep(wait_before)

    with open(src, encoding="utf-8") as fh:
        content = fh.read()

    # 1) publish the new manifest atomically (the per-feed raw it references is already on
    #    disk), THEN 2) bump the sentinel — the all-or-nothing commit the watcher acts on.
    _atomic_write(live_manifest, content)

    cur = 0
    try:
        with open(sentinel, encoding="utf-8") as fh:
            first = fh.readline().strip()
        if first.isdigit():
            cur = int(first)
    except OSError:
        pass
    _atomic_write(sentinel, "{}\n".format(cur + 1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
