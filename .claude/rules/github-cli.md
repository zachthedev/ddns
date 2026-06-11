# GitHub CLI Targeting

This repository is a fork of an actively maintained upstream
(willswire/unifi-ddns). The gh CLI resolves missing repo arguments from git
remotes, and in a fork that resolution can land on the upstream parent
instead of this repository.

## Rules

- Every gh command that creates or modifies something visible to others
  (`pr create`, `pr close`, `pr comment`, `issue create`, `issue comment`,
  `release create`, `repo edit`, label or milestone changes) must carry an
  explicit `--repo zachthedev/uddns`. Never rely on default resolution for
  these commands.
- `gh pr create` additionally requires explicit `--base` and `--head`
  branches, even when `--repo` is present.
- Read-only gh commands (`pr view`, `pr checks`, `run view`, `api` GETs) may
  omit `--repo` only after `gh repo set-default` has been confirmed to point
  at zachthedev/uddns in the current clone (`gh repo set-default --view`).
- Anything aimed at the upstream repository (PRs, issues, comments on
  willswire/unifi-ddns) happens only on an explicit request that names the
  upstream; the request being about "the repo" always means this fork.
- When a script or automation invokes gh, the same explicitness applies
  inside the script.
