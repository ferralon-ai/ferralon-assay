// Package pipeline runs the deterministic Assess stages — advisory intake, codebase
// inventory, disqualification discovery, symbol mapping, reachability and ingress, and
// exposure footprint — in order over an Assessment through the Orchestrator. It also holds
// the advisory sources the intake stage reads and the per-ecosystem version comparators the
// disqualification axis uses.
package pipeline
