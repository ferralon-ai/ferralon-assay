package verdict

import "github.com/ferralon-ai/ferralon-assay/artifact"

// ObjectionSchemaVersion is the versioned schema id for an adversarial-review objection
// embedded in a PoE (RFC 0010 §Adversarial review).
const ObjectionSchemaVersion = "tegron.objection.v1"

// Objection records a sustained adversarial-review downgrade. It is the compact summary
// embedded in a PoE; the full critic record lives in the referenced "critic_objection"
// artifact (CriticReport). nil on the PoE when the critic did not run (below the triviality
// threshold) or ran and failed to break the verdict — additive and omitempty so every
// existing PoE JSON stays valid.
type Objection struct {
	SchemaVersion string `json:"schema_version"` // = ObjectionSchemaVersion
	// AttackedLabel is the provisional (pre-downgrade) verdict label the critic attacked,
	// e.g. "exploitable", "reasoned_not_exploitable".
	AttackedLabel string `json:"attacked_label"`
	// AttackClass is the RFC 0010 attack the adversary sustained:
	// benign_explanation | flaky_reproducer | missed_path | grounds_thinner | direction_flip.
	AttackClass string `json:"attack_class"`
	// Rationale is the one-sentence basis the adversary sustained (also the new ReasonedGrounds).
	Rationale string `json:"rationale"`
	// FromLabel / ToLabel record the downgrade applied.
	FromLabel string `json:"from_label"`
	ToLabel   string `json:"to_label"`
	// Episode is the adversary Episode ID; CriticReport refs the full "critic_objection" record.
	Episode      string        `json:"episode"`
	CriticReport *artifact.Ref `json:"critic_report,omitempty"`
}
