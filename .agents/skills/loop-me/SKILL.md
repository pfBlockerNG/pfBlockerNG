---
name: loop-me
description: Grill me about specs for the workflows I want to build, within this workspace.
disable-model-invocation: true
argument-hint: "A workflow to design, or nothing to go find one"
---
Run stateful `/grilling` session. Only output: **workflow** specs. Use grilling discipline — relentless, one question at a time, recommended answer attached to each — aimed at vocabulary and goal below. Create, edit, delete specs as grilling resolves things.

## The loop lens

**Loop** = recurring pattern in user's life: career, week, morning, single repeated activity. Picture life as loops within loops — reveals how predictable activities really are. That what make them worth **delegating**. Use lens to find loops worth specifying, propose ones user not noticed.

**Workflow** = spec of one loop, made real. Run workflow on loop — loop is running instantiation. Workflows live in `workflows/*.md`, are source of truth.

## Vocabulary

Shared language. Reach for it only when workflow call for it — never checklist. **Mandate nothing structural**: workflow need no AI, no checkpoint, no schedule unless grilling show it does.

- **Trigger** — what fires each run: **event** (new email, new issue) or **schedule** (every morning). Event-triggering usually more efficient.
- **Checkpoint** — human-in-loop point where user asked to verify or decide. Some workflows have none, run autonomously; some use no AI at all.
- **Push right** — defer checkpoint as far as it go. Do maximal work before involving human, so they asked once, late, with everything prepared.
- **Brief** — what checkpoint presents: tight, decision-ready summary — what produced, why, link down to asset itself — never raw output. User read brief, not draft. Speed of review imperative.

## Definition of done

Workflow spec done when implementer agent could build it without asking single question. Grill until then. Nothing done while question remain.

## The workspace

- `workflows/*.md` — one spec per workflow.
- `NOTES.md` — raw notes on user's world: tools they use, channels they process, own terminology for both. Empty or thin → interview them about their world before specifying anything. Sharpen fuzzy terms into canonical ones as they surface, record here.
