# AGENTS.md · terraform-aws-atlex-connect

**Public.** What customers install in their AWS accounts: the read-only cross-account role, EventBridge forwarding and the `atlex-tf-report` CI step, plus a generated CloudFormation template (Repo Architecture §2.4). Anything committed here is world-readable: never commit Atlex internals, account IDs or secrets.

This is a stub. The full rules for every Atlex repo live in [`Atlex-SI/atlex` AGENTS.md](https://github.com/Atlex-SI/atlex/blob/master/AGENTS.md), and the governing docs in [`Atlex-SI/atlex` docs/](https://github.com/Atlex-SI/atlex/tree/master/docs). Until this repo grows its own section, these apply:

- **Jira is the live status.** Work comes from a story in project KAN; pick it with `/story` in the `atlex` repo.
- **Every change is a PR** from a `kan-<n>-<slug>` branch off `master`. The PR title carries the Jira key, e.g. `feat(scope): summary (KAN-12)`; CI fails without it. Commit messages carry it too, by convention.
- **Merge rule (TB-24).** Green CI and the Sift review, then the author merges. Rebase-merge only.
- **No more than 2 epics in flight** per founder.
- **CI here is a placeholder.** EP07 (atlex-connect) replaces it with `terraform fmt -check` + `terraform validate`.
