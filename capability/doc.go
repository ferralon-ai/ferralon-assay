// Package capability defines the per-language capability manifest: the static, up-front
// declaration of what a language's analyzer supports. It is the compile-time complement to the
// per-run Partiality disclosure (plugin.Partiality).
//
// This package is a LEAF — it imports NEITHER plugin NOR report. That is deliberate: both plugin
// (whose Op Response carries a *capability.Manifest) and report (which cites Manifest.Version as a
// plain string) reference this package without an import cycle. Putting a plugin.Partiality field
// on Manifest would create capability→plugin, and with plugin→capability already present that is a
// direct cycle; honest absence is instead the capability-local Supported bool. A manifest's absence
// is a binary static fact ("published or not-yet"), not the three-valued per-run partiality that
// governs analysis evidence.
package capability
