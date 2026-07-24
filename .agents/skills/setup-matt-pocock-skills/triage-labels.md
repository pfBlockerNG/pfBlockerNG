# Triage Labels

The skills speak in terms of five canonical triage roles. This file maps those roles to the actual label strings used in this repo's issue tracker.

| Label in mattpocock/skills | Label in our tracker | Meaning                                  |
| -------------------------- | -------------------- | ---------------------------------------- |
| `needs-triage`             | `needs-triage`       | Maintainer needs to evaluate this issue  |
| `needs-info`               | `needs-info`         | Waiting on reporter for more information |
| `ready-for-agent`          | `ready-for-agent`    | Fully specified, ready for an AFK agent  |
| `ready-for-human`          | `ready-for-human`    | Requires human implementation            |
| `wontfix`                  | `wontfix`            | Will not be actioned                     |

When a skill mentions a role (e.g. "apply the AFK-ready triage label"), use the corresponding label string from this table.

Edit the right-hand column to match whatever vocabulary you actually use.

## Category roles

The two **category** roles map to the issue's native **type**, not a label:

| Category role | Our tracker      | How to set                        |
| ------------- | ---------------- | --------------------------------- |
| `bug`         | type **Bug**     | `gh issue edit <n> --type Bug`    |
| `enhancement` | `enhancement` label | `gh issue edit <n> --add-label enhancement` |

The `bug` label has been retired — categorise bugs with the type only. Migrate
`enhancement` to a type the same way if/when you retire that label.
