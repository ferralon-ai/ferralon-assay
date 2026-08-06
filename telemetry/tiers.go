package telemetry

// instrumentTier is the coverage-tier catalog: it maps every metric instrument in the
// tegron OTEL convention to the LOWEST TEGRON_OTEL_LEVEL at which that instrument's stream
// is exported: 17 essential, 20 standard, 3 full, plus the reused gen_ai.* pair and the
// foundational health counter. It is the single source of truth the View builder consumes
// to drop higher-tier streams (see viewsForLevel).
//
// Every instrument is *registered* unconditionally by its emit site — creating an instrument
// is cheap; the SDK Views built from this catalog decide what actually aggregates and
// exports. The emit sites land with the instruments they meter; the tier for each name is
// already fixed here, so no later change re-decides gating and the tier lever is complete
// from the start. `tegron.telemetry.up` is the only instrument with a live emit site today;
// the rest are catalogued ahead of their emitters so a lower level provably drops a
// higher-tier stream now.
//
// No entry carries owner_id — per-tenant identity is never a metric dimension; it lives on
// spans and DB columns only.
var instrumentTier = map[string]Level{
	// Foundation: the health counter proving the OTLP pipe end-to-end.
	"tegron.telemetry.up": LevelEssential,

	// Essential — business-action counters + the top COGS drivers (17).
	"tegron.assessment.launch.count":      LevelEssential,
	"tegron.assessment.run.count":         LevelEssential,
	"tegron.assessment.run.duration":      LevelEssential,
	"tegron.scan.count":                   LevelEssential,
	"tegron.verdict.count":                LevelEssential,
	"tegron.prove.kickoff.count":          LevelEssential,
	"tegron.billing.event.count":          LevelEssential,
	"tegron.platform.installation.count":  LevelEssential,
	"gen_ai.client.token.usage":           LevelEssential, // #1 COGS, reused verbatim
	"gen_ai.client.operation.duration":    LevelEssential, // reused verbatim
	"tegron.sandbox.trial.count":          LevelEssential,
	"tegron.sandbox.trial.duration":       LevelEssential,
	"tegron.sandbox.build.duration":       LevelEssential,
	"tegron.plugin.call.count":            LevelEssential,
	"tegron.plugin.call.duration":         LevelEssential,
	"tegron.prove.fire.duration":          LevelEssential,
	"tegron.platform.ingest.filing.count": LevelEssential,

	// Standard — durations / bytes / stage / aux-ops signals (20).
	"tegron.hypothesis.dispatched.count":        LevelStandard,
	"tegron.sandbox.run.active":                 LevelStandard,
	"tegron.fuzz.campaign.count":                LevelStandard,
	"tegron.fuzz.campaign.duration":             LevelStandard,
	"tegron.stage.duration":                     LevelStandard,
	"tegron.checkout.duration":                  LevelStandard,
	"tegron.evidence.bundle.bytes":              LevelStandard,
	"tegron.evidence.bundle.files":              LevelStandard,
	"tegron.episode.bytes":                      LevelStandard,
	"tegron.platform.ingest.bytes":              LevelStandard,
	"tegron.platform.report_run.count":          LevelStandard,
	"tegron.prove.fire.queue_wait":              LevelStandard,
	"tegron.console.detail_render.duration":     LevelStandard,
	"tegron.platform.provision.completed.count": LevelStandard,
	"tegron.recall.query.count":                 LevelStandard,
	"tegron.recall.hits":                        LevelStandard,
	"tegron.platform.access_audit.count":        LevelStandard,
	"tegron.vcs.line_changes.count":             LevelStandard,
	"tegron.repository.loc":                     LevelStandard,
	"tegron.repository.languages":               LevelStandard,

	// Full — vanity / high-card / blocked probe (3).
	"tegron.platform.advisory_dispatch.count": LevelFull,
	"tegron.curation.promoted.count":          LevelFull,
	"tegron.repository.contributors":          LevelFull,
}
