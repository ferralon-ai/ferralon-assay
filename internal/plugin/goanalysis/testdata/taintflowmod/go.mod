module tegron.test/taintflowmod

go 1.26

require (
	github.com/go-chi/chi/v5 v5.0.0
	tegron.test/nethttp v0.0.0
)

// Hermetic stand-ins, shared with chimod: chi registration makes the handler an
// ingress, and the net/http stand-in's read methods are body-less in the SSA program,
// exactly as real net/http's are (only the module's own packages get bodies).
replace (
	github.com/go-chi/chi/v5 => ../chimod/chiv5stub
	tegron.test/nethttp => ../chimod/nethttpstub
)
