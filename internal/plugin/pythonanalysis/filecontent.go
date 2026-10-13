package pythonanalysis

import (
	"bytes"
	"os"
	"path"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// fileContent is what readInstallFile found a file to be.
type fileContent int

const (
	// contentText is text the scan reads: UTF-8 or any single-byte encoding as is, and UTF-16
	// or UTF-32 decoded to UTF-8.
	contentText fileContent = iota
	// contentArchive is an archive or compressed file. It can bundle Python distributions or
	// install commands the scan does not unpack.
	contentArchive
	// contentExecutable is a native or Java executable. It can bundle an interpreter and
	// Python distributions (a PyInstaller or zipapp build).
	contentExecutable
	// contentBinary is other binary data (an image, a font): it carries neither text nor an
	// archive.
	contentBinary
)

// binaryHeadSize is how much of a file decides whether it is text.
const binaryHeadSize = 8000

// archiveExts are the suffixes of archive, compressed and packaged-distribution files.
var archiveExts = []string{".zip", ".pex", ".pyz", ".pyzw", ".whl", ".egg", ".tar", ".tgz", ".tbz", ".tbz2", ".txz",
	".tzst", ".tlz", ".gz", ".bz2", ".xz", ".zst", ".lz", ".lz4", ".lzma", ".z", ".7z", ".rar", ".jar", ".war",
	".conda", ".squashfs", ".sqfs", ".deb", ".rpm", ".apk", ".cab", ".cpio"}

// archiveMagic are the leading bytes of archive and compressed formats.
var archiveMagic = [][]byte{
	[]byte("PK\x03\x04"), []byte("PK\x05\x06"), []byte("PK\x07\x08"), // zip, wheel, egg, jar
	{0x1f, 0x8b},                       // gzip
	[]byte("BZh"),                      // bzip2
	{0xfd, '7', 'z', 'X', 'Z', 0x00},   // xz
	{0x28, 0xb5, 0x2f, 0xfd},           // zstd
	{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}, // 7z
	[]byte("Rar!\x1a\x07"),             // rar
	[]byte("LZIP"),                     // lzip
	{0x04, 0x22, 0x4d, 0x18},           // lz4
	[]byte("hsqs"), []byte("sqsh"),     // squashfs
	[]byte("070707"), []byte("070701"), []byte("070702"), // cpio
	[]byte("!<arch>\n"),      // ar (deb)
	{0xed, 0xab, 0xee, 0xdb}, // rpm
	[]byte("MSCF"),           // cab
}

// executableMagic are the leading bytes of native and Java executables.
var executableMagic = [][]byte{
	{0x7f, 'E', 'L', 'F'},
	{0xfe, 0xed, 0xfa, 0xce}, {0xfe, 0xed, 0xfa, 0xcf}, {0xce, 0xfa, 0xed, 0xfe}, {0xcf, 0xfa, 0xed, 0xfe}, // Mach-O
	{0xca, 0xfe, 0xba, 0xbe}, // Mach-O universal, Java class
	[]byte("MZ"),             // PE
}

// readInstallFile reads the file at p and reports what it is. Text comes back decoded; any
// other kind comes back with no data.
func readInstallFile(p string) ([]byte, fileContent, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, contentText, err
	}
	data, kind := classifyContent(path.Base(p), data)
	return data, kind, nil
}

// classifyContent decides what data, the content of a file named name, is.
func classifyContent(name string, data []byte) ([]byte, fileContent) {
	if isArchive(name, data) {
		return nil, contentArchive
	}
	if text, ok := decodeUnicode(data); ok {
		return text, contentText
	}
	head := data[:min(len(data), binaryHeadSize)]
	if bytes.IndexByte(head, 0) < 0 {
		return data, contentText
	}
	for _, m := range executableMagic {
		if bytes.HasPrefix(data, m) {
			return nil, contentExecutable
		}
	}
	return nil, contentBinary
}

// isArchive reports an archive by suffix, by leading magic, by a tar header, or by a zip
// end-of-central-directory record anywhere in the file's tail (a zip behind a prefix: a pex,
// a zipapp, a self-extracting archive).
func isArchive(name string, data []byte) bool {
	lower := strings.ToLower(name)
	for _, ext := range archiveExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	for _, m := range archiveMagic {
		if bytes.HasPrefix(data, m) {
			return true
		}
	}
	if len(data) >= 262 && bytes.Equal(data[257:262], []byte("ustar")) {
		return true
	}
	// The end-of-central-directory record sits within 22 bytes plus a comment of at most
	// 64 KiB of the end.
	tail := data[max(0, len(data)-(22+65535)):]
	return bytes.Contains(tail, []byte("PK\x05\x06"))
}

// decodeUnicode decodes UTF-8 with a byte-order mark, UTF-32 with one, and UTF-16 with or
// without one, to UTF-8. ok is false for anything else.
func decodeUnicode(data []byte) ([]byte, bool) {
	switch {
	case bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}):
		return data[3:], true
	case bytes.HasPrefix(data, []byte{0xff, 0xfe, 0, 0}):
		return decodeUTF32(data[4:], false), true
	case bytes.HasPrefix(data, []byte{0, 0, 0xfe, 0xff}):
		return decodeUTF32(data[4:], true), true
	case bytes.HasPrefix(data, []byte{0xff, 0xfe}):
		return decodeUTF16(data[2:], false), true
	case bytes.HasPrefix(data, []byte{0xfe, 0xff}):
		return decodeUTF16(data[2:], true), true
	}
	if be, ok := bomlessUTF16(data); ok {
		return decodeUTF16(data, be), true
	}
	return nil, false
}

// bomlessUTF16 recognizes UTF-16 text without a byte-order mark: in the head, nearly every
// code unit's high byte is NUL (ASCII-range text) and its low byte is not.
func bomlessUTF16(data []byte) (bigEndian, ok bool) {
	head := data[:min(len(data), binaryHeadSize)&^1]
	if len(head) < 4 {
		return false, false
	}
	var zeroEven, zeroOdd int
	for i := 0; i < len(head); i += 2 {
		if head[i] == 0 {
			zeroEven++
		}
		if head[i+1] == 0 {
			zeroOdd++
		}
	}
	units := len(head) / 2
	switch {
	case zeroOdd*10 >= units*9 && zeroEven*10 <= units:
		return false, true
	case zeroEven*10 >= units*9 && zeroOdd*10 <= units:
		return true, true
	}
	return false, false
}

func decodeUTF16(b []byte, bigEndian bool) []byte {
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		if bigEndian {
			units = append(units, uint16(b[i])<<8|uint16(b[i+1]))
		} else {
			units = append(units, uint16(b[i+1])<<8|uint16(b[i]))
		}
	}
	return []byte(string(utf16.Decode(units)))
}

func decodeUTF32(b []byte, bigEndian bool) []byte {
	out := make([]byte, 0, len(b)/4)
	for i := 0; i+3 < len(b); i += 4 {
		var r uint32
		if bigEndian {
			r = uint32(b[i])<<24 | uint32(b[i+1])<<16 | uint32(b[i+2])<<8 | uint32(b[i+3])
		} else {
			r = uint32(b[i+3])<<24 | uint32(b[i+2])<<16 | uint32(b[i+1])<<8 | uint32(b[i])
		}
		out = utf8.AppendRune(out, rune(r))
	}
	return out
}
