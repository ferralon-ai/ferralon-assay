# Ferralon Assay — GitHub Action

Ferralon Assay is a checksum-pinned security scanner delivered as a composite GitHub Action. It runs
in **your own runner** — your source never leaves it — fetches a pinned, checksum-verified scanner
release at run time (no binary is ever committed into your repository), and files its findings.

```yaml
- name: Run the Ferralon Assay
  uses: ferralon-ai/ferralon-assay@<sha>
  with:
    mode: baseline
    target: .
```

Pin the Action by **commit SHA** (`@<sha>`). The SHA transitively pins the exact scanner bytes the
Action fetches (via the `scanner-version` + `scanner-sha256` baked into the Action), and a built-in
**drift guard** fails the run loudly on any checksum mismatch. Nothing runs that you did not pin.

## Automatic upgrades (and how to opt out)

Ferralon Assay is an **automated, continuously-improved** system. For the repositories Ferralon
maintains, we keep the pinned `@<sha>` on the **latest verified cut by default**, so you receive
advisory-corpus and engine improvements without chasing pins by hand.

Each upgrade arrives as a **normal, reviewable, revertible pull request** that changes **only** the
`@<sha>` on the `uses:` line — nothing else in your workflow is touched. The PR is gated by your own
CI and by the Action's checksum drift guard before it can merge. The automation **never**
force-pushes and **never** rewrites your history. You review and merge on your own schedule; the
upgrade is a proposal, not a push.

### Hold a pin — one comment, honored

If you want a repository (or a single workflow) to **stay** on its current pin, add a trailing
`# ferralon:hold` comment to the pin line:

```yaml
  uses: ferralon-ai/ferralon-assay@<sha> # ferralon:hold
```

A held pin is **never** auto-rewritten, and the marker is **never** removed or overridden by the
automation. Remove the comment when you want to resume automatic upgrades. The hold is the single,
durable opt-out signal — it lives exactly where the pin lives, so it travels with the pin.

## What a pinned upgrade changes

- **Only** the `@<sha>` reference on the `uses: ferralon-ai/ferralon-assay@…` line.
- Surrounding content — your `with:` inputs, comments, indentation, other steps — is left untouched.
- Before an upgrade PR is opened, the automation verifies the target cut's pinned `scanner-sha256`
  against its published scanner release; if that checksum does not resolve, **no PR is opened**. The
  upgrade then lands as a normal, reviewable pull request, still gated by your own CI and the
  Action's drift guard before it merges — the automation proposes the upgrade, your pipeline decides.

## Questions

The upgrade PRs are opened by the Ferralon Team bot; reply on any PR with questions. This document is
the durable contract the PR body links to.
