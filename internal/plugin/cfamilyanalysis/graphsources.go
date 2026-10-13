package cfamilyanalysis

import (
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/cfamilyanalysis/compiledb"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// GraphSources is the part of the build context a graph engine reads: the compilation database
// whose translation units name the files to analyze and each one's language, and the gaps of the
// build context itself, which every graph result built on it inherits.
type GraphSources struct {
	// Partiality is the build context's own: no_manifest with no database or no generator,
	// unreadable or malformed entries, TUs in languages the lane does not analyze, and flags
	// the database records but the lane did not read.
	Partiality plugin.Partiality
	// DB is the database read, or nil when none was found or it could not be read. A graph
	// engine then reads the source tree instead, under the no_manifest reason above.
	DB *compiledb.DB
}

// ReadGraphSources derives the build context of the C/C++ tree at buildDir and returns what a
// graph engine needs of it.
func ReadGraphSources(buildDir string) (GraphSources, error) {
	bc, err := deriveBuildContext(buildDir)
	if err != nil {
		return GraphSources{}, err
	}
	return GraphSources{Partiality: bc.Partiality, DB: bc.DB}, nil
}
