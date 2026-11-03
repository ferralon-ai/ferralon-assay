# Peer PR checklist

## Once per clone

Run the hook installer once in each clone you push peer-order branches from:

```
scripts/install-githooks.sh
```

It points the clone's `core.hooksPath` at the tracked `scripts/githooks`, whose `pre-push` hook
refuses a push that creates a second remote branch for an order id: one a branch on the remote
already carries, or two new branches for one id in the same push. If `core.hooksPath` already
names another directory (a `.husky`, say), the installer prints it with the config it comes from
(local or global) and stops; re-run it with `--force` to set it in the clone's local config, which
leaves a global setting itself alone. It names the hooks git will stop running when it switches.

Name an order branch with its id as a whole token, `asy-<n>-<slug>` or `eric-req-<slug>`. An
eric-req id runs to the first `/`, `_` or `.`, so a suffix joined with a hyphen becomes part of the
id; put any suffix after one of those (`eric-req-<slug>/<suffix>`), as the header of
`scripts/githooks/pre-push` explains. A push that creates an order branch is refused when the
remote's branches cannot be listed (offline, say); the same header gives the exit codes and the
`PR_ORDER_ALLOW=1` bypass.
