package pipeline

// houseCanaryFacts are the first-party house canaries: demo records this module wrote to exercise
// the pipeline end to end, mostly over its own com.example / tegron-corpus / stand-in packages. Some
// mirror a public advisory (the Airflow entry aliases its CVE), but none is sourced from a feed or
// stands for advisory coverage, and a scan reads them only when -include-house-canaries opts it in.
// Their symbol sets were written here alongside the repros they name; the source marks them BuiltIn
// rather than tagging a symbol provenance.
var houseCanaryFacts = map[string]AdvisoryFacts{
	"FERRALON-APP-DOS-0001": {
		PURL:       "pkg:golang/tegron/corpus/dos",
		Symbols:    []string{"main.expandHandler"},
		CWEs:       []string{"CWE-400"},
		Summary:    "uncontrolled resource consumption: expandHandler allocates a slice sized by an attacker-controlled count with no upper bound, faulting the process",
		Provenance: Provenance{TrustTier: TrustFirstParty},
	},
	"FERRALON-JAVA-SSRF-0001": {
		PURL:       "pkg:maven/com.example.web/ssrf",
		Symbols:    []string{"UrlFetcher.fetch"},
		CWEs:       []string{"CWE-918"},
		Summary:    "server-side request forgery: a servlet forwards an attacker-controlled target through UrlFetcher.fetch to an outbound HTTP request with no allowlist",
		Provenance: Provenance{TrustTier: TrustFirstParty},
	},
	"FERRALON-JAVA-SPRING-SSRF-0001": {
		PURL:       "pkg:maven/com.example.web/spring-ssrf",
		Symbols:    []string{"UrlServiceImpl.fetch"},
		CWEs:       []string{"CWE-918"},
		Summary:    "server-side request forgery: a Spring @RestController reaches UrlServiceImpl.fetch through an @Autowired interface field; the sink issues an outbound request with no allowlist",
		Provenance: Provenance{TrustTier: TrustFirstParty},
	},
	"FERRALON-JAVA-DEP-0001": {
		Coordinate:     "com.example.lib:widget",
		UpperExclusive: "1.4.0",
		FixedVersion:   "1.4.0",
		VersionScheme:  "maven",
		PURL:           "pkg:maven/com.example.lib/widget",
		Summary:        "deserialization flaw in com.example.lib:widget fixed in 1.4.0",
		Provenance:     Provenance{TrustTier: TrustFirstParty},
	},
	"FERRALON-JS-SSRF-0001": {
		PURL:       "pkg:npm/tegron-corpus-ssrf",
		Symbols:    []string{"fetchUrl"},
		CWEs:       []string{"CWE-918"},
		Summary:    "server-side request forgery: an Express route forwards an attacker-controlled target through fetchUrl to an outbound HTTP request with no allowlist",
		Provenance: Provenance{TrustTier: TrustFirstParty},
	},
	"FERRALON-JS-DEP-0001": {
		Coordinate:     "left-pad",
		UpperExclusive: "1.4.0",
		FixedVersion:   "1.4.0",
		VersionScheme:  "npm",
		PURL:           "pkg:npm/left-pad",
		Summary:        "prototype pollution in left-pad fixed in 1.4.0",
		Provenance:     Provenance{TrustTier: TrustFirstParty},
	},
	// The PyPI and NuGet dependency canaries carry no VersionScheme: advisoryIntake.Run derives it
	// from the PURL (pkg:pypi→pypi, pkg:nuget→nuget).
	"FERRALON-PY-DEP-0001": {
		Coordinate:     "flask",
		UpperExclusive: "2.3.2",
		FixedVersion:   "2.3.2",
		PURL:           "pkg:pypi/flask",
		Summary:        "reflected header injection in flask fixed in 2.3.2",
		Provenance:     Provenance{TrustTier: TrustFirstParty},
	},
	"FERRALON-NET-DEP-0001": {
		Coordinate:     "Newtonsoft.Json",
		UpperExclusive: "13.0.1",
		FixedVersion:   "13.0.1",
		PURL:           "pkg:nuget/Newtonsoft.Json",
		Summary:        "insecure default deserialization in Newtonsoft.Json fixed in 13.0.1",
		Provenance:     Provenance{TrustTier: TrustFirstParty},
	},
	// The Airflow experimental REST API shipped with no access control by default (the
	// CVE-2020-13927 family) and was deleted wholesale in Airflow 3.0.0 (PR #41434). The sink is
	// first-party to apache-airflow, so there is no version-range fix and the version axis fails
	// open; at the fix commit both the sink module and its decorated handler are gone, which flips
	// reachable_candidate to not_exploitable.
	"FERRALON-PY-AIRFLOW-EXPAPI-0001": {
		Aliases:    []string{"CVE-2020-13927"},
		PURL:       "pkg:pypi/apache-airflow",
		Symbols:    []string{"airflow.api.common.experimental.get_code.get_code"},
		CWEs:       []string{"CWE-306"},
		Summary:    "missing authentication: the experimental REST API exposes an unauthenticated get_code sink that reads arbitrary DAG source off disk; the experimental API has no access control by default and was removed wholesale in Airflow 3.0.0",
		Provenance: Provenance{TrustTier: TrustFirstParty},
	},
}

// houseCanarySource serves houseCanaryFacts.
type houseCanarySource struct{}

// NewHouseCanarySource returns the house canaries as an AdvisorySource. An entrypoint installs it
// only when the scan opted the canaries in.
func NewHouseCanarySource() AdvisorySource { return houseCanarySource{} }

func (houseCanarySource) Lookup(vulnID string) (AdvisoryFacts, bool) {
	facts, ok := houseCanaryFacts[vulnID]
	if !ok {
		return AdvisoryFacts{}, false
	}
	facts.BuiltIn = true
	return facts, true
}
