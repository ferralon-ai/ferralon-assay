// projection.go
//
// Package projection converts a verdict into industry-standard output formats:
// SARIF 2.1.0, OpenVEX, and SSVC v2.
//
// All projections are READ-ONLY over an existing verdict — they never alter
// direction, strength, or confidence, and they never upgrade a reasoned lean
// to a proven finding (RFC 0003 §Standard projections; RFC 0001 inv.5).
//
// Report-driven entry points (the scan path this module ships):
//   - projection.ProjectReportSARIF(report) → *SARIFLog
//   - projection.ProjectReportVEX(report)   → *VEXDocument
//   - projection.ProjectReportHTML(report)  → []byte
//
// PoE-driven entry points:
//   - projection.ProjectSARIF(poe) → *SARIFLog
//   - projection.ProjectSSVC(poe)  → *SSVCDecision
//   - projection.ProjectRedactedPoE(poe, opts) → *RedactedPoE
//
// Marshal* variants return ([]byte, error) for direct serialization.
//
// The PoE-driven OpenVEX projector is deliberately NOT here. Its "affected"
// branch asserts a proven-exploitable verdict, which this module cannot
// produce; it lives service-side alongside its caller. Only the OpenVEX wire
// vocabulary it shares with ProjectReportVEX stays here (vex.go).
package projection
