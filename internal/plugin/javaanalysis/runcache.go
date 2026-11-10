package javaanalysis

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/depreach"
)

type runCacheDirKey struct{}

// WithRunCacheDir returns ctx carrying the run cache: a directory the host creates for one scan and
// removes after it (see plugin.WithJavaRunCacheDir). Each op runs in its own process, so without it
// every advisory searches the whole program again from every root. Without it, or with an empty
// dir, nothing is cached.
func WithRunCacheDir(ctx context.Context, dir string) context.Context {
	return context.WithValue(ctx, runCacheDirKey{}, dir)
}

// closureFormat names the on-disk layout of one root's search; a change to it, or to what a
// search records, changes every key.
const closureFormat = "assay-java-closure-v1"

// closureStore keeps each root's whole search (depreach.Engine.Closure) in the run cache, so a
// later advisory's process answers a sink no root's search reached without searching again. key
// hashes every input those searches read; an entry under any other key is never read.
type closureStore struct {
	dir string
	key []byte
}

// newClosureStore returns the store for one engine state, or nil when there is no run cache or
// no build id to key it on. parts are the inputs the searches read beyond the plugin itself.
func newClosureStore(ctx context.Context, parts ...string) *closureStore {
	dir, _ := ctx.Value(runCacheDirKey{}).(string)
	if dir == "" {
		return nil
	}
	id := pluginBuildID()
	if id == "" {
		return nil
	}
	return &closureStore{dir: dir, key: closureKey(append([]string{closureFormat, id}, parts...))}
}

// closureStoreFor returns the store for the searches bytecodeReachability runs on rc's engine
// under linked, keyed on what those searches read: the loaded JARs, the first-party classes and
// the classpath (rc.key), the first-party classes in full, the build graph file, the launch
// entry, and the linked bit. nil when nothing is cached, or an input cannot be read to key on.
func closureStoreFor(ctx context.Context, rc *reachClosure, fp *firstPartyBytecode, entry launchEntry, linked bool, opts ...Option) *closureStore {
	if dir, _ := ctx.Value(runCacheDirKey{}).(string); dir == "" {
		return nil
	}
	classes, err := exactEncoding(fp.classes)
	if err != nil {
		return nil
	}
	graph := "none"
	if file := resolveOptions(opts).graphFile; file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil
		}
		graph = sha256Hex(b)
	}
	return newClosureStore(ctx,
		"engine="+rc.key,
		"classes="+sha256Hex(classes),
		"graph="+graph,
		"mains="+strings.Join(entry.mains, "\x00"),
		"launch="+strings.Join(entry.reasons, "\x00"),
		"linked="+strconv.FormatBool(linked))
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// closureKey hashes parts, each length-prefixed so no two lists collide.
func closureKey(parts []string) []byte {
	h := sha256.New()
	for _, p := range parts {
		fmt.Fprintf(h, "%d:%s", len(p), p)
	}
	return h.Sum(nil)
}

func (s *closureStore) path(root classfile.MethodRef) string {
	h := sha256.New()
	h.Write(s.key)
	r := root.String()
	fmt.Fprintf(h, "%d:%s", len(r), r)
	return filepath.Join(s.dir, "java-closure-"+hex.EncodeToString(h.Sum(nil)))
}

// load seeds e with root's stored search, when one exists, decodes whole and fits e. Any other
// entry is a miss: e then searches as if nothing were stored.
func (s *closureStore) load(e *depreach.Engine, root classfile.MethodRef) bool {
	if s == nil || e.HasClosure(root) {
		return false
	}
	b, err := os.ReadFile(s.path(root))
	if err != nil {
		return false
	}
	bits, miss, err := decodeClosure(b, s.key, root)
	if err != nil {
		return false
	}
	return e.SetClosure(root, bits, miss)
}

// save stores root's search, when e holds one it can export. A failed write leaves no entry.
func (s *closureStore) save(e *depreach.Engine, root classfile.MethodRef) {
	if s == nil {
		return
	}
	bits, miss, ok := e.Closure(root)
	if !ok {
		return
	}
	path := s.path(root)
	if _, err := os.Stat(path); err == nil {
		return
	}
	b, err := encodeClosure(s.key, root, bits, miss)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(s.dir, "java-closure-*.tmp")
	if err != nil {
		return
	}
	_, wErr := tmp.Write(b)
	cErr := tmp.Close()
	if wErr != nil || cErr != nil || os.Rename(tmp.Name(), path) != nil {
		_ = os.Remove(tmp.Name())
	}
}

// closureHeader leads an entry. Key and Root repeat what the path hashes, so an entry is only
// ever read for the search it records.
type closureHeader struct {
	Format string
	Key    string
	Root   string
	Words  int
	Miss   depreach.Result
}

// encodeClosure lays an entry out as a JSON header line, the bitset words little-endian, and a
// sha256 over both.
func encodeClosure(key []byte, root classfile.MethodRef, bits []uint64, miss depreach.Result) ([]byte, error) {
	hdr, err := json.Marshal(closureHeader{Format: closureFormat, Key: hex.EncodeToString(key), Root: root.String(), Words: len(bits), Miss: miss})
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.Write(hdr)
	buf.WriteByte('\n')
	if err := binary.Write(&buf, binary.LittleEndian, bits); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(buf.Bytes())
	buf.Write(sum[:])
	return buf.Bytes(), nil
}

var errClosureCorrupt = errors.New("java closure entry corrupt")

// decodeClosure reads an entry encodeClosure wrote for key and root. A short, altered or foreign
// entry is errClosureCorrupt, never a partial answer.
func decodeClosure(b, key []byte, root classfile.MethodRef) ([]uint64, depreach.Result, error) {
	if len(b) < sha256.Size {
		return nil, depreach.Result{}, errClosureCorrupt
	}
	body, sum := b[:len(b)-sha256.Size], b[len(b)-sha256.Size:]
	if want := sha256.Sum256(body); !bytes.Equal(want[:], sum) {
		return nil, depreach.Result{}, errClosureCorrupt
	}
	nl := bytes.IndexByte(body, '\n')
	if nl < 0 {
		return nil, depreach.Result{}, errClosureCorrupt
	}
	var hdr closureHeader
	if err := json.Unmarshal(body[:nl], &hdr); err != nil {
		return nil, depreach.Result{}, errClosureCorrupt
	}
	rest := body[nl+1:]
	if hdr.Format != closureFormat || hdr.Key != hex.EncodeToString(key) || hdr.Root != root.String() ||
		len(rest)%8 != 0 || hdr.Words != len(rest)/8 {
		return nil, depreach.Result{}, errClosureCorrupt
	}
	bits := make([]uint64, hdr.Words)
	if err := binary.Read(bytes.NewReader(rest), binary.LittleEndian, bits); err != nil {
		return nil, depreach.Result{}, errClosureCorrupt
	}
	return bits, hdr.Miss, nil
}

var buildID struct {
	once sync.Once
	id   string
}

// pluginBuildID hashes this process's executable, so an entry another build of the analysis wrote
// is never read. "" when the executable cannot be read: nothing is then cached.
var pluginBuildID = func() string {
	buildID.once.Do(func() {
		path, err := os.Executable()
		if err != nil {
			return
		}
		f, err := os.Open(path)
		if err != nil {
			return
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return
		}
		buildID.id = hex.EncodeToString(h.Sum(nil))
	})
	return buildID.id
}
