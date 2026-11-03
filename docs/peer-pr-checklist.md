# Peer-order PR checklist

Use this before opening a pull request for a peer order. One order gets one PR.

1. Run the duplicate check with the order's id:

   ```
   scripts/pr-dup-check.sh <order-id>
   ```

   It lists open PRs (through `gh`) and remote branches, and exits 1, naming each one, if the id
   already appears in a PR's title, body or branch name, or in a remote branch name. It exits 0 when
   nothing carries the id.

2. If it exits 1, **do not open a second PR.** Push your revisions to the existing PR's branch
   instead, and say what changed in a comment on that PR. If the existing PR is abandoned or wrong,
   ask its author or the reviewer before replacing it.

3. If it exits 0, open the PR and put the order id in the title or branch name so the next
   contributor's check finds it.

4. If `gh` is not signed in, the check covers remote branches only (it says so on stderr). Look at
   the repository's open PRs yourself before opening one.
