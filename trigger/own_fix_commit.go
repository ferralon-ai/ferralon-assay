package trigger

import (
	"fmt"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// ownFixCommitUnanswered returns the fix commit of an advisory on the scanned project itself, whose
// own release version was not established, when the advisory's fix commit would have settled it
// and the checkout's history could not say whether it holds that commit. It returns "" otherwise,
// including for a row with a package, which names the version it was placed at.
func ownFixCommitUnanswered(store artifact.Store, assessmentID string, pkg *report.Package) string {
	if pkg != nil || !ownReleaseUnversioned(store, assessmentID) {
		return ""
	}
	return disqualRecord(store, assessmentID).FixCommitUnanswered
}

// ownFixCommitUnansweredDetail is the detail of a row ownFixCommitUnanswered holds.
func ownFixCommitUnansweredDetail(commit string) string {
	short := commit
	if len(short) > 12 {
		short = short[:12]
	}
	return fmt.Sprintf("This advisory is on this repository's own code, and the release version of this checkout could not be established. "+
		"The advisory names the commit that fixes it, %s, but whether this checkout's history contains that commit could not be answered, "+
		"because the history is shallow or could not be read, so the path found is not judged against it. "+
		"A checkout with its full history and tags answers it: with actions/checkout, set fetch-depth: 0.", short)
}
