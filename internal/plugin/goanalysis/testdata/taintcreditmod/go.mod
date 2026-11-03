module tegron.test/taintcreditmod

go 1.26

require (
	github.com/go-chi/chi/v5 v5.0.0
	tegron.test/nethttp v0.0.0
)

// Hermetic stand-ins, shared with chimod and taintflowmod.
replace (
	github.com/go-chi/chi/v5 => ../chimod/chiv5stub
	tegron.test/nethttp => ../chimod/nethttpstub
)
