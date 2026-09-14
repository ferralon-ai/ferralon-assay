module tegron.test/sshmod

go 1.26

require golang.org/x/crypto/ssh v0.0.0

// Hermetic stand-in: the SSH ingress detector matches the package PATH
// golang.org/x/crypto/ssh; the local stub supplies that path with no network fetch.
replace golang.org/x/crypto/ssh => ./sshstub
