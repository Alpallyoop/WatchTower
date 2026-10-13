# Proposal 0005 — Repository governance items for the owner

| | |
|---|---|
| Status | Open; each item is an owner decision, none is made by this change |
| Date | 2026-10-13 |

## 1. Default branch

GitHub's default branch is `main`, an orphan history of 11 documentation and policy commits
(last 2026-02-03) that shares no commits with `master`, where all code lives. Anyone cloning the
repository gets `main` and no code. Options: make `master` the default branch and archive `main`
as a tag; or merge the `main` documents into `master` and then switch. Proposed: the first.

## 2. Licence

There is no `LICENSE` file. Without one, nobody else may use, copy or modify the code, which
blocks reuse by other Constellation repositories under different ownership. Choosing a licence
is the owner's decision; none was added.

## 3. Legacy v1 scripts

`scripts/` holds the v1 runners, selftests and tools (57 tracked files) and `release/` the v1 CLI
bundle. They are untouched and outside the v2 gate. Proposed: once proposal 0001 is accepted,
move them to `legacy/v1/` with their freeze evidence, and keep `docs/history/` as the record.

## 4. Local-only hygiene on the development host

The WBS v1 audit found items that exist only in the local working copy, so this branch cannot fix
them:

- a directory literally named ``k in $Map.Keys){ [void]$keys.Add([string]$k) }`` from a broken
  redirect;
- `proofs/keys/watchtower_authority_ed25519.COMPROMISED.*` and `.PASSPHRASE.*` private keys:
  move them to an offline store or destroy them, and never rotate them back into trust;
- 18 `proofs/trust/*.bak_*` files, a stray top-level `workbench/`, untracked UI duplicates;
- uncommitted edits and 3,682 staged `ui/node_modules` deletions on branch
  `audit/hygiene-fixes-20260826`. The deletions and the selftest/gitignore edits are included
  in this branch, so after merging, the local copy can be reset to `master`.

## 5. Bridge CORS

The local bridge server (not in this repository) answered every origin
(`Access-Control-Allow-Origin: *`). If it moves to live-state-surgeon (proposal 0001), restrict it
to the local UI origin there.
