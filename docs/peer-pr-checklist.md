# Peer-order PR checklist

Use this before opening a pull request for a peer order. One order gets one PR.

1. Run the duplicate check with the order's id:

   ```
   scripts/pr-dup-check.sh <order-id>
   ```

   It lists open PRs (through `gh`) and remote branches, and exits 1, naming each one, if the id
   already appears in a PR's title, body or branch name, or in a remote branch name. It exits 0 when
   nothing carries the id and the remote branches were read. It exits 2 when the remote branches
   could not be listed (no `origin`, offline), or when the check itself failed partway, so it did
   not finish; fix that and run it again. Exit 1 only ever means something was found.

2. If it exits 1, **do not open a second PR.** Push your revisions to the existing PR's branch
   instead, and say what changed in a comment on that PR. If the existing PR is abandoned or wrong,
   ask its author or the reviewer before replacing it. The id also matches a longer id it is a
   hyphenated prefix of (`eric-req-fix-184` matches `eric-req-fix-184-docs`), so check that the
   named PR or branch is for the same order before pushing to it.

3. If it exits 0, open the PR and put the order id in the title or branch name so the next
   contributor's check finds it. Exit 0 means at least the remote branches were checked; read
   stderr for whether the open PRs were too (step 4).

4. If `gh` is not installed or fails (not signed in, offline, rate-limited), the check covers remote
   branches only and says so on stderr, with gh's own error text. It also says so when gh returns
   200 open PRs, its listing limit, since any past that were not checked. Exit 0 with the
   "branches only" note means just that: PRs from forks, and PRs whose branch does not carry the
   id, were not checked. In either case look at the repository's open PRs yourself before opening
   one.

5. If it exits 2, do not open a PR: the check did not finish. Its stderr says which listing could
   not be read, or where the check failed. Any open PR it names on stdout already carries the id, so
   step 2 applies to it.
