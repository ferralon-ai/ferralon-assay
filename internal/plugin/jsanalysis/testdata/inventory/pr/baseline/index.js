// Presence of a .js source makes checkout.DetectLanguage classify this vendored_repro
// fixture as "js" so ResolveSBOM routes to the JS inventory plugin. The dependency graph
// itself lives in the lockfile; this file has no runtime role and is never executed.
module.exports = {};
