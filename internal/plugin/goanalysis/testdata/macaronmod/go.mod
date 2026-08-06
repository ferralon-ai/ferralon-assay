module tegron.test/macaronmod

go 1.26

require gopkg.in/macaron.v1 v1.0.0

// Hermetic stand-in: the detector matches the package PATH gopkg.in/macaron.v1; the
// local stub supplies that path with no network fetch.
replace gopkg.in/macaron.v1 => ./macaronstub
