# Anonymous-identity enforcement

This is a **public repository**. Every commit must be attributed to the shared
anonymous identity — never to an individual — so that no personal name or email
is ever published in git history.

The identity is defined in [`identity`](./identity).

## One-time setup after cloning

```bash
git config core.hooksPath .githooks
git config user.name  "$(sed -n 's/^NAME="\(.*\)"/\1/p'  .githooks/identity)"
git config user.email "$(sed -n 's/^EMAIL="\(.*\)"/\1/p' .githooks/identity)"
```

(`core.hooksPath` is a local setting and cannot be committed, so each clone must
run the first line once.)

## Enforcement layers

| Layer | File | Catches |
|-------|------|---------|
| Local, pre-commit | `pre-commit` | misconfigured `user.name`/`user.email` before a commit is made |
| Local, pre-push | `pre-push` | any non-anonymous author/committer about to leave the machine (`--author` overrides, cherry-picks, merges) |
| Server | GitHub repository ruleset → *Restrict commit metadata* | anything the local hooks miss; the authoritative guarantee |

The email must **not** be an address linked to any individual's GitHub account,
or GitHub will backlink the commits to that person.
