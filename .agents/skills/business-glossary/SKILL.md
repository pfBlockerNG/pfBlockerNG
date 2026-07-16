---
name: business-glossary
description: Extract a business-facing glossary from the current conversation, flagging cross-department term drift and proposing canonical business terms. Saves to BUSINESS_GLOSSARY.md. Use when user wants to define business/stakeholder terms, build a glossary for non-engineers, harden business terminology, or reconcile how different departments (Sales, Finance, Support, Growth) use the same word differently.
disable-model-invocation: true
---

# Business Glossary

Extract and formalize business/stakeholder terminology from the current conversation into a consistent glossary, saved to a local file. Sibling of `/ubiquitous-language`, aimed at business meaning instead of code-domain meaning — the ambiguity here is a word carrying different meaning per department, not per module.

## Process

1. **Scan the conversation** for business-relevant nouns, verbs, and concepts (metrics, roles, process stages, artifacts)
2. **Identify problems**:
   - Same word used for different concepts across departments/roles (ambiguity)
   - Different words used for the same concept (synonyms)
   - Vague or overloaded terms (a metric with no agreed formula, a status with no agreed boundary)
3. **Propose a canonical glossary** with opinionated term choices
4. **Write to `BUSINESS_GLOSSARY.md`** in the working directory using the format below
5. **Output a summary** inline in the conversation

## Output Format

Write a `BUSINESS_GLOSSARY.md` file with this structure:

```md
# Business Glossary

## Revenue lifecycle

| Term         | Definition                                                     | Who says it differently                          |
| ------------ | ---------------------------------------------------------------| -------------------------------------------------- |
| **Churn**    | A customer whose paid subscription lapses without renewal      | Finance: any account with $0 MRR (includes trials) |
| **MRR**      | Monthly recurring revenue from active paid subscriptions       | Sales: sometimes includes one-time setup fees      |

## Roles

| Term                | Definition                                              | Who says it differently                    |
| ------------------- | -------------------------------------------------------- | ------------------------------------------- |
| **Account owner**   | The person with billing authority on an account          | Support: conflates with primary contact     |
| **Champion**        | The internal stakeholder driving adoption, not billing    | Sales: sometimes used interchangeably with account owner |

## Relationships

- A **Churn** event closes exactly one **Account**'s **MRR** contribution to zero
- A **Champion** may or may not be the **Account owner**

## Example dialogue

> **PM:** "Is a downgrade to the free tier **Churn**?"
> **Domain expert:** "Not for Product — we track it as **Downgrade**, a separate metric. Finance counts it as **Churn** because MRR hits zero."
> **PM:** "So our dashboard's 'Churn' number won't match Finance's board deck?"
> **Domain expert:** "Right, unless we label them **Product churn** and **Finance churn** explicitly."

## Flagged ambiguities

- "Churn" was used to mean both **Product churn** (cancels paid plan) and **Finance churn** (any account at $0 MRR, including trials) — these are distinct metrics with different denominators.
```

## Rules

- **Be opinionated.** When multiple words exist for the same concept, pick the best one and list who else uses a different word or meaning.
- **Flag conflicts explicitly.** If a term is used ambiguously across departments/roles in the conversation, call it out in the "Flagged ambiguities" section with a clear recommendation.
- **Only include terms relevant for business stakeholders.** Skip code symbols, table names, or implementation details unless they carry business-decision weight (e.g. a plan name customers see).
- **Keep definitions tight.** One sentence max. Define what it IS, not how it's computed internally.
- **Show relationships.** Use bold term names and express cardinality where obvious.
- **Attribute drift to who, not just that.** The "Who says it differently" column names the department/role (Sales, Finance, Support, Growth, Legal) — a business glossary's value is knowing WHOSE definition you're overriding, since each has budget/comp/reporting riding on their version.
- **Group terms into multiple tables** when natural clusters emerge (e.g. by lifecycle stage, department, or artifact type). Each group gets its own heading and table. If all terms belong to a single cohesive area, one table is fine — don't force groupings.
- **Write an example dialogue.** A short conversation (3-5 exchanges) between a PM/founder and a domain expert (or between two departments) that demonstrates how the terms interact naturally and surfaces where two teams would silently disagree.

## Re-running

When invoked again in the same conversation:

1. Read the existing `BUSINESS_GLOSSARY.md`
2. Incorporate any new terms from subsequent discussion
3. Update definitions if understanding has evolved
4. Re-flag any new ambiguities
5. Rewrite the example dialogue to incorporate new terms
