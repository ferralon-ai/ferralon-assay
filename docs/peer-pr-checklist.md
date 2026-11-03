# Peer PR checklist

## Once per clone

Run the hook installer once in each clone you push peer-order branches from:

```
scripts/install-githooks.sh
```

It points the clone's `core.hooksPath` at the tracked `scripts/githooks`, whose `pre-push` hook
refuses a push that creates a second remote branch for an order id: one a branch on the remote
already carries, or two new branches for one id in the same push. If the clone already sets
`core.hooksPath` to something else (a `.husky`, say), the installer prints it and stops; re-run it
with `--force` to replace it. It names the hooks git will stop running when it switches.
