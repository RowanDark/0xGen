---
search: false
---

# Project Board

0xgen uses a GitHub Projects board to visualise work and keep releases on track. The board lives at `https://github.com/orgs/<ORG>/projects/<ID>` (replace with the organisation and project identifiers for your deployment).

## Columns

1. **Ready** – well-scoped issues that are prioritised for upcoming work.
2. **In-Progress** – tasks actively being implemented. Keep assignees updated via issue comments.
3. **In-Review** – changes awaiting code review or final verification.
4. **Done** – shipped improvements. Close linked issues when they land here.

## Wiring issues

- Each issue should have a clear title, acceptance criteria, and links to specs/notes.
- Use the "Projects" sidebar on the issue to add it to the board.
- Automation tips:
  - Enable "auto add" on the Ready column for new issues tagged with your sprint label.
  - Configure workflows so merged pull requests move linked issues to **Done** automatically.

## Tips

- Break up large efforts into smaller cards so progress is visible.
- Review the board during standups to ensure priorities are aligned.
- Archive cards in **Done** at the end of each sprint to keep the board light-weight.

_Note:_ This repository snapshot cannot create the GitHub Project automatically—set it up in the GitHub UI following the steps above.
