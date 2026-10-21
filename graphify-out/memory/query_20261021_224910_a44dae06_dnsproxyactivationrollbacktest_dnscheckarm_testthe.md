---
type: "query"
date: "2026-10-21T22:49:10.799975+00:00"
question: "DnsProxyActivationRollbackTest dnsCheckArm testTheBootCheckRollsBackAStartThatNeverBecomesReady"
contributor: "graphify"
outcome: "useful"
---

# Q: DnsProxyActivationRollbackTest dnsCheckArm testTheBootCheckRollsBackAStartThatNeverBecomesReady

## Answer

Merged #3556 supplies real CLI-arm execution seam dnsCheckArm and assertRolledBackWithNotices in DnsProxyActivationRollbackTest.php. Added boot/tick x missing Unbound/foreign listener scenarios before #3560 production edit; final RED145tests1048assertions41failures.

## Outcome

- Signal: useful