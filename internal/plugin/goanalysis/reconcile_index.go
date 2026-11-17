package goanalysis

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"os"
	"slices"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// The reconcile index is the run-cache entry a result with a path reads in place of the edges entry.
// Reconcile asks of the graph's edges one question, whether each adjacent pair along a path is an
// edge, and of the rest of the graph only its partiality and reflectReach, so the index holds
// exactly that: the partiality and reflectReach, and a sorted table of one digest per edge. Reading it
// costs a read and a checksum of a file a fraction of the edges entry's size, where the edges entry
// costs a JSON decode of the whole graph in every advisory's process.
//
// Layout: magic, u32 length and body of the JSON meta, u64 edge count, that many edgeDigestSize
// digests in ascending order, and a sha256 of everything before it. The entry is one rename, so it
// is whole or absent; a reader that finds anything else (wrong length, bad checksum, bad meta)
// distrusts it and reads the edges entry, never an empty graph, which would read as "no path
// corroborated" for every advisory.
const (
	reconcileIndexMagic = "FRRCIDX1"
	edgeDigestSize      = 16
	checksumSize        = sha256.Size
)

type reconcileIndexMeta struct {
	Partiality   plugin.Partiality   `json:"partiality"`
	ReflectReach map[string][]string `json:"reflect_reach"`
}

// edgeDigest names the edge from caller to callee. Every field of both symbols is in it, length
// prefixed, so two edges share a digest only on a sha256 collision truncated to edgeDigestSize bytes.
func edgeDigest(caller, callee plugin.Symbol) [edgeDigestSize]byte {
	h := sha256.New()
	for _, s := range [2]plugin.Symbol{caller, callee} {
		for _, f := range [...]string{string(s.Kind), s.Package, s.Enclosing, s.Name, s.Descriptor, s.DisplayName, s.SCIP} {
			var n [8]byte
			binary.BigEndian.PutUint64(n[:], uint64(len(f)))
			h.Write(n[:])
			h.Write([]byte(f))
		}
		if s.Generated {
			h.Write([]byte{1})
		} else {
			h.Write([]byte{0})
		}
	}
	var d [edgeDigestSize]byte
	copy(d[:], h.Sum(nil))
	return d
}

// encodeReconcileIndex is the index entry for g.
func encodeReconcileIndex(g reconcileGraph) ([]byte, error) {
	meta, err := json.Marshal(reconcileIndexMeta{Partiality: g.CallGraph.Partiality, ReflectReach: g.ReflectReach})
	if err != nil {
		return nil, err
	}
	digests := make([][edgeDigestSize]byte, len(g.CallGraph.Edges))
	for i, e := range g.CallGraph.Edges {
		digests[i] = edgeDigest(e.Caller, e.Callee)
	}
	slices.SortFunc(digests, func(a, b [edgeDigestSize]byte) int { return bytes.Compare(a[:], b[:]) })
	digests = slices.Compact(digests)

	out := make([]byte, 0, len(reconcileIndexMagic)+4+len(meta)+8+len(digests)*edgeDigestSize+checksumSize)
	out = append(out, reconcileIndexMagic...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(meta)))
	out = append(out, meta...)
	out = binary.BigEndian.AppendUint64(out, uint64(len(digests)))
	for _, d := range digests {
		out = append(out, d[:]...)
	}
	sum := sha256.Sum256(out)
	return append(out, sum[:]...), nil
}

// reconcileIndex is a decoded, verified index entry.
type reconcileIndex struct {
	meta    reconcileIndexMeta
	digests []byte // ascending, edgeDigestSize each
}

// decodeReconcileIndex verifies b whole before it trusts any of it.
func decodeReconcileIndex(b []byte) (reconcileIndex, bool) {
	const head = len(reconcileIndexMagic) + 4
	if len(b) < head+8+checksumSize || string(b[:len(reconcileIndexMagic)]) != reconcileIndexMagic {
		return reconcileIndex{}, false
	}
	body, trailer := b[:len(b)-checksumSize], b[len(b)-checksumSize:]
	if sum := sha256.Sum256(body); !bytes.Equal(sum[:], trailer) {
		return reconcileIndex{}, false
	}
	metaLen := uint64(binary.BigEndian.Uint32(b[len(reconcileIndexMagic):head]))
	if metaLen > uint64(len(body)-head-8) {
		return reconcileIndex{}, false
	}
	metaEnd := head + int(metaLen)
	n := binary.BigEndian.Uint64(body[metaEnd : metaEnd+8])
	rest := body[metaEnd+8:]
	if n > uint64(len(rest))/edgeDigestSize || uint64(len(rest)) != n*edgeDigestSize {
		return reconcileIndex{}, false
	}
	var meta reconcileIndexMeta
	if err := json.Unmarshal(body[head:metaEnd], &meta); err != nil {
		return reconcileIndex{}, false
	}
	return reconcileIndex{meta: meta, digests: rest}, true
}

func (x reconcileIndex) has(d [edgeDigestSize]byte) bool {
	i := sort.Search(len(x.digests)/edgeDigestSize, func(i int) bool {
		return bytes.Compare(x.digests[i*edgeDigestSize:(i+1)*edgeDigestSize], d[:]) >= 0
	})
	return i*edgeDigestSize < len(x.digests) && bytes.Equal(x.digests[i*edgeDigestSize:(i+1)*edgeDigestSize], d[:])
}

// graphFor is the reconcile graph restricted to what paths read of it: the partiality and reflect
// reach, and those adjacent pairs along a path that the index holds as edges. reconcile reads no
// other edge, so the result built from it is the result the whole graph gives.
func (x reconcileIndex) graphFor(paths []plugin.ReachPath) reconcileGraph {
	var edges []plugin.CallEdge
	for _, p := range paths {
		for i := 0; i+1 < len(p.Trace); i++ {
			if x.has(edgeDigest(p.Trace[i], p.Trace[i+1])) {
				edges = append(edges, plugin.CallEdge{Caller: p.Trace[i], Callee: p.Trace[i+1]})
			}
		}
	}
	return reconcileGraph{
		CallGraph:    plugin.CallGraphResult{Partiality: x.meta.Partiality, Edges: edges},
		ReflectReach: x.meta.ReflectReach,
	}
}

// storeReconcileIndex stores g's index beside its edges entry in dir under key.
func storeReconcileIndex(dir string, key []string, g reconcileGraph) {
	b, err := encodeReconcileIndex(g)
	if err != nil {
		return
	}
	writeRunCacheEntry(dir, "reconcile-index", runCachePath(dir, "reconcile-index", key), b)
}

// readReconcileIndex returns the cached index for key, and whether it can be trusted: it verifies
// whole, and the edges entry it indexes is present.
func readReconcileIndex(dir string, key []string) (reconcileIndex, bool) {
	b, err := os.ReadFile(runCachePath(dir, "reconcile-index", key))
	if err != nil {
		return reconcileIndex{}, false
	}
	x, ok := decodeReconcileIndex(b)
	if !ok {
		return reconcileIndex{}, false
	}
	if _, err := os.Stat(runCachePath(dir, "reconcile", key)); err != nil {
		return reconcileIndex{}, false
	}
	return x, true
}

// reconcileGraphForPaths returns the reconcile graph for a result that derived paths: from the
// index when it can be trusted, otherwise the whole graph (reconcileCallGraph), after which the
// index is stored again so the advisories that follow read it.
func reconcileGraphForPaths(ctx context.Context, buildDir string, known []string, load func() (*LoadResult, error), paths []plugin.ReachPath) (reconcileGraph, error) {
	dir := RunCacheDir(ctx)
	key := reconcileKey(ctx, buildDir, known)
	if dir != "" {
		if x, ok := readReconcileIndex(dir, key); ok {
			return x.graphFor(paths), nil
		}
	}
	g, err := reconcileCallGraph(ctx, buildDir, known, load)
	if err != nil {
		return reconcileGraph{}, err
	}
	if dir != "" {
		if _, ok := readReconcileIndex(dir, key); !ok {
			storeReconcileIndex(dir, key, g)
		}
	}
	return g, nil
}
