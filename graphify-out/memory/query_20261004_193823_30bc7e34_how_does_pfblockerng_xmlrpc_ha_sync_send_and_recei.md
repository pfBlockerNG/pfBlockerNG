---
type: "query"
date: "2026-10-04T19:38:23.122091+00:00"
question: "How does pfBlockerNG XMLRPC HA sync send and receive package sections (pfblockerng_sync_sections, pfblockerng_plugin_xmlrpc_recv, pfblockerng_do_xmlrpc_sync)?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["pfblockerng_plugin_xmlrpc_recv()", "pfblockerng_plugin_xmlrpc_send()", "pfblockerng_do_xmlrpc_sync()"]
---

# Q: How does pfBlockerNG XMLRPC HA sync send and receive package sections (pfblockerng_sync_sections, pfblockerng_plugin_xmlrpc_recv, pfblockerng_do_xmlrpc_sync)?

## Answer

The graph located the three sync entry points in pfblockerng.inc (pfblockerng_do_xmlrpc_sync L21494, pfblockerng_plugin_xmlrpc_send L21540, pfblockerng_plugin_xmlrpc_recv L21566) and their tests (SyncSectionsTest, XmlrpcSyncIdnTargetTest); CodeGraph then supplied the verbatim bodies used for issue 3443's per-field sync specification.

## Outcome

- Signal: useful

## Source Nodes

- pfblockerng_plugin_xmlrpc_recv()
- pfblockerng_plugin_xmlrpc_send()
- pfblockerng_do_xmlrpc_sync()