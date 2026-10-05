---
type: "query"
date: "2026-10-05T00:23:58.390322+00:00"
question: "How does pfBlockerNG XMLRPC HA sync send and receive package sections (pfblockerng_plugin_xmlrpc_send, pfblockerng_plugin_xmlrpc_recv, pfblockerng_do_xmlrpc_sync, pfblockerng_sync_sections)?"
contributor: "graphify"
outcome: "useful"
---

# Q: How does pfBlockerNG XMLRPC HA sync send and receive package sections (pfblockerng_plugin_xmlrpc_send, pfblockerng_plugin_xmlrpc_recv, pfblockerng_do_xmlrpc_sync, pfblockerng_sync_sections)?

## Answer

Graph located pfblockerng_do_xmlrpc_sync() at pfblockerng.inc:21494, pfblockerng_plugin_xmlrpc_send() at :21540, pfblockerng_plugin_xmlrpc_recv() at :21566 (devel ac5abbed); used to anchor spec line-reference re-verification for #3443.

## Outcome

- Signal: useful