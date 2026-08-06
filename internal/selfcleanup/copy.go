package selfcleanup

import "fmt"

// User-visible copy for the cleanup ladder. Clinical register (per the
// clinical-register-terminology guide): factual, no alarm, no "exploit", no blame —
// this is routine housekeeping after an uninstall, and every string says so and
// notes the change is reversible by re-installing.

const removalCommitMsg = "Remove Ferralon Assay workflow (app uninstalled)"

// prTitle / issueTitle are the exact titles the design-constants contract froze.
const (
	prTitle    = "Ferralon removed — merge to finish cleanup"
	issueTitle = "Ferralon removed — one manual step to finish cleanup"
)

// prBody names the ref THIS run's actuator actually deletes — g.cfg.StateRef, never
// statestore.DefaultRef and never a hand-spelled literal. DeleteStateRef always runs
// (rung 1/2 last, rung 3 first — see ladder.go), so by the time this text is read
// the deletion has already happened; naming any ref other than g.cfg.StateRef here
// would tell an operator who set a custom state-ref that a ref no run touched was
// removed, and leave their actual state behind. See the "single source of truth"
// doc comment on brand.RefNamespace.
func (g *gitActuator) prBody() string {
	return "The Ferralon GitHub App was uninstalled from this repository, so the scan no longer reports to Ferralon.\n\n" +
		"This pull request removes the leftover workflow file `.github/workflows/ferralon-assay.yml`. " +
		"Merging it completes the cleanup — nothing else runs afterward, and the durable state ref (`" + g.cfg.StateRef + "`) has already been removed.\n\n" +
		"Uninstalled by mistake? You can close this pull request and re-install the Ferralon App; scanning resumes with no further action.\n"
}

// issueBody carries the single manual git command to finish cleanup. It names
// g.cfg.StateRef (the ref this run's actuator actually deleted), same reasoning as
// prBody above.
func (g *gitActuator) issueBody() string {
	return fmt.Sprintf(
		"The Ferralon GitHub App was uninstalled from this repository. The scan has disabled its own workflow, so nothing runs anymore, and the durable state ref (`%s`) has been removed.\n\n"+
			"One manual step remains — remove the leftover workflow file:\n\n"+
			"```sh\n"+
			"git rm %s\n"+
			"git commit -m \"Remove Ferralon Assay workflow\"\n"+
			"git push\n"+
			"```\n\n"+
			"Uninstalled by mistake? Re-install the Ferralon App and re-enable the workflow — no cleanup needed.\n",
		g.cfg.StateRef, g.cfg.WorkflowPath)
}
