package tlog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Checkpoint is a C2SP tlog-checkpoint: the log's identity (origin), its
// size and root hash. Signed as a note, it commits the operator to the
// exact contents of the first Size entries.
type Checkpoint struct {
	Origin string
	Size   uint64
	Root   Hash
}

// Marshal returns the checkpoint body (the note text).
func (c Checkpoint) Marshal() []byte {
	return []byte(fmt.Sprintf("%s\n%d\n%s\n", c.Origin, c.Size, base64.StdEncoding.EncodeToString(c.Root[:])))
}

// ParseCheckpoint parses a checkpoint body. Extension lines are ignored.
func ParseCheckpoint(text []byte) (Checkpoint, error) {
	lines := strings.Split(string(text), "\n")
	if len(lines) < 4 || lines[len(lines)-1] != "" {
		return Checkpoint{}, errors.New("tlog: malformed checkpoint")
	}
	origin := lines[0]
	if !validName(origin) {
		return Checkpoint{}, fmt.Errorf("tlog: invalid checkpoint origin %q", origin)
	}
	if lines[1] == "" || (len(lines[1]) > 1 && lines[1][0] == '0') {
		return Checkpoint{}, errors.New("tlog: malformed checkpoint size")
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("tlog: malformed checkpoint size: %w", err)
	}
	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(root) != len(Hash{}) {
		return Checkpoint{}, errors.New("tlog: malformed checkpoint root hash")
	}
	c := Checkpoint{Origin: origin, Size: size}
	copy(c.Root[:], root)
	return c, nil
}

// --- Signed notes (https://c2sp.org/signed-note), Ed25519 only. ---

const algEd25519 = 0x01

var (
	sigSplit  = []byte("\n\n")
	sigPrefix = []byte("\u2014 ") // em dash + space
	// ErrNoValidSignature means the note carries no valid signature from the expected key.
	ErrNoValidSignature = errors.New("tlog: note has no valid signature from the expected key")
)

// NoteSigner signs checkpoint notes.
type NoteSigner interface {
	Public() ed25519.PublicKey
	Sign(msg []byte) ([]byte, error)
}

func validName(name string) bool {
	return name != "" && utf8.ValidString(name) &&
		strings.IndexFunc(name, unicode.IsSpace) < 0 && !strings.Contains(name, "+")
}

func keyHash(name string, pub ed25519.PublicKey) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write([]byte{algEd25519})
	h.Write(pub)
	return binary.BigEndian.Uint32(h.Sum(nil))
}

// VerifierKey returns the note verifier key string "name+hash+key" that
// witnesses and other note tooling use to identify a log key.
func VerifierKey(name string, pub ed25519.PublicKey) string {
	return fmt.Sprintf("%s+%08x+%s", name, keyHash(name, pub),
		base64.StdEncoding.EncodeToString(append([]byte{algEd25519}, pub...)))
}

// SignNote signs text (which must end in a newline) under key name.
func SignNote(text []byte, name string, s NoteSigner) ([]byte, error) {
	if !validName(name) {
		return nil, fmt.Errorf("tlog: invalid key name %q", name)
	}
	if len(text) == 0 || text[len(text)-1] != '\n' || bytes.Contains(text, sigSplit) {
		return nil, errors.New("tlog: note text must end with a newline and contain no blank lines")
	}
	sig, err := s.Sign(text)
	if err != nil {
		return nil, err
	}
	blob := make([]byte, 4+len(sig))
	binary.BigEndian.PutUint32(blob, keyHash(name, s.Public()))
	copy(blob[4:], sig)
	var out bytes.Buffer
	out.Write(text)
	out.WriteByte('\n')
	out.Write(sigPrefix)
	out.WriteString(name)
	out.WriteByte(' ')
	out.WriteString(base64.StdEncoding.EncodeToString(blob))
	out.WriteByte('\n')
	return out.Bytes(), nil
}

// OpenNote verifies that msg carries a valid signature by (name, pub) and
// returns the signed text. Signatures from other keys (for example
// witnesses) are ignored here.
func OpenNote(msg []byte, name string, pub ed25519.PublicKey) ([]byte, error) {
	for i := 0; i < len(msg); {
		r, size := utf8.DecodeRune(msg[i:])
		if (r < 0x20 && r != '\n') || (r == utf8.RuneError && size == 1) {
			return nil, errors.New("tlog: malformed note")
		}
		i += size
	}
	split := bytes.LastIndex(msg, sigSplit)
	if split < 0 {
		return nil, errors.New("tlog: malformed note: no signature block")
	}
	text, sigs := msg[:split+1], msg[split+2:]
	if len(sigs) == 0 || sigs[len(sigs)-1] != '\n' {
		return nil, errors.New("tlog: malformed note signature block")
	}
	want := keyHash(name, pub)
	for _, line := range bytes.Split(sigs[:len(sigs)-1], []byte("\n")) {
		if !bytes.HasPrefix(line, sigPrefix) {
			return nil, errors.New("tlog: malformed note signature line")
		}
		fields := strings.SplitN(string(line[len(sigPrefix):]), " ", 2)
		if len(fields) != 2 || fields[0] != name {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(fields[1])
		if err != nil || len(blob) < 5 || binary.BigEndian.Uint32(blob) != want {
			continue
		}
		if ed25519.Verify(pub, text, blob[4:]) {
			return text, nil
		}
	}
	return nil, ErrNoValidSignature
}

// SignCheckpoint signs a checkpoint using its origin as the key name.
func SignCheckpoint(c Checkpoint, s NoteSigner) ([]byte, error) {
	return SignNote(c.Marshal(), c.Origin, s)
}

// OpenCheckpoint verifies a signed checkpoint against the log key. If
// origin is empty, the origin claimed in the checkpoint is used; callers
// that know which log they expect should always pass it.
func OpenCheckpoint(msg []byte, origin string, pub ed25519.PublicKey) (Checkpoint, error) {
	if origin == "" {
		first, _, ok := bytes.Cut(msg, []byte("\n"))
		if !ok {
			return Checkpoint{}, errors.New("tlog: malformed checkpoint")
		}
		origin = string(first)
	}
	text, err := OpenNote(msg, origin, pub)
	if err != nil {
		return Checkpoint{}, err
	}
	c, err := ParseCheckpoint(text)
	if err != nil {
		return Checkpoint{}, err
	}
	if c.Origin != origin {
		return Checkpoint{}, fmt.Errorf("tlog: checkpoint origin %q does not match expected %q", c.Origin, origin)
	}
	return c, nil
}
