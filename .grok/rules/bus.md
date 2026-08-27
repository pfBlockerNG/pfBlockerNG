# Smoke-1 bus — Grok must line-wake

When this session is on the smoke-1 agent bus (`PFB_AGENT=grok-dev` / `grok-smoke`),
arm `pfb-msg serve` with the Grok **monitor** tool and `persistent: true`.

**Never** run it as a background bash job (`run_terminal_command` / `background: true`).
That surface notifies only when the process **exits**. `pfb-msg serve` never exits on a
new message (one stdout line per file), so unread mail piles up and the session looks
frozen. Background bash also dies at the harness 10 h cap, which is what finally
wakes a wedged session — too late.

`pfb-msg watch` is the one-shot form (one line, then exit). `serve` is the
session-length form. Both print one stdout line per message; the monitor tool
turns each line into a turn. Feed them to **monitor**, not to background bash.

If the monitor dies, restart it the same way. Do not "keep working" with the bus
off unless the owner said to stop comms.
