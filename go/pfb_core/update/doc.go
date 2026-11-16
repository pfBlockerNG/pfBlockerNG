// Package update owns Core's singleton Update admission and presentation (issue #3941, map #3813). The independent worker owns
// an admitted transaction, its lifetime flock and durable request/result/status receipts; Core stop or cancellation ends only
// observation. A restarted Core observes a live worker or reconciles its terminal receipt instead of relaunching the Update.
package update
