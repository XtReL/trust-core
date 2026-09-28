package event

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// PredicateLogGenesis is the predicate type of entry 0 of every log epoch
// k >= 2. It links the new epoch to the frozen state of the previous one
// (ADR 0002).
const PredicateLogGenesis = "https://github.com/XtReL/trust-core/log-genesis/v1"

// Rotation kinds. Planned: the old key co-signs the genesis. Unplanned: the
// old key is lost or compromised (indistinguishable), only the new key
// signs, and a verifier must accept the new key explicitly.
const (
	RotationPlanned   = "planned"
	RotationUnplanned = "unplanned"
)

// LogGenesis is the log-genesis/v1 predicate.
type LogGenesis struct {
	Epoch             int    `json:"epoch"`
	PredecessorOrigin string `json:"predecessorOrigin"`
	PredecessorSize   uint64 `json:"predecessorSize"`
	// PredecessorRoot is the frozen root, base64 as in a checkpoint.
	PredecessorRoot string `json:"predecessorRoot"`
	// PredecessorCheckpoint is the exact signed-note text of the freeze
	// checkpoint of the previous epoch.
	PredecessorCheckpoint string `json:"predecessorCheckpoint"`
	PredecessorKeyID      string `json:"predecessorKeyID"`
	NewKeyID              string `json:"newKeyID"`
	Rotation              string `json:"rotation"`
	// Note is free text; it does not affect verification.
	Note string `json:"note,omitempty"`
}

func validKeyID(id string) bool {
	if len(id) != 64 || strings.ToLower(id) != id {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

// RootBytes decodes PredecessorRoot.
func (g LogGenesis) RootBytes() ([]byte, error) {
	root, err := base64.StdEncoding.DecodeString(g.PredecessorRoot)
	if err != nil || len(root) != 32 {
		return nil, errors.New("event: genesis predecessorRoot must be base64 of 32 bytes")
	}
	return root, nil
}

// Validate checks the structural rules of the genesis predicate. It does
// not check signatures or the predecessor log: that is verify.Chain's job.
func (g LogGenesis) Validate() error {
	if g.Epoch < 2 {
		return fmt.Errorf("event: genesis epoch must be >= 2, got %d", g.Epoch)
	}
	switch g.Rotation {
	case RotationPlanned, RotationUnplanned:
	default:
		return fmt.Errorf("event: genesis rotation must be %q or %q, got %q", RotationPlanned, RotationUnplanned, g.Rotation)
	}
	if g.PredecessorOrigin == "" {
		return errors.New("event: genesis predecessorOrigin is required")
	}
	if g.PredecessorCheckpoint == "" {
		return errors.New("event: genesis predecessorCheckpoint is required")
	}
	if !validKeyID(g.PredecessorKeyID) || !validKeyID(g.NewKeyID) {
		return errors.New("event: genesis key IDs must be 64 lowercase hex characters")
	}
	if g.PredecessorKeyID == g.NewKeyID {
		return errors.New("event: genesis newKeyID equals predecessorKeyID (the key was not rotated)")
	}
	if _, err := g.RootBytes(); err != nil {
		return err
	}
	return nil
}

// NewLogGenesis builds a validated Event carrying a genesis predicate. The
// subject is the previous epoch: name = its origin, sha256 = hex frozen root.
func NewLogGenesis(g LogGenesis) (Event, error) {
	if err := g.Validate(); err != nil {
		return Event{}, err
	}
	root, _ := g.RootBytes()
	raw, err := json.Marshal(g)
	if err != nil {
		return Event{}, err
	}
	ev := Event{
		Subjects:      []Subject{{Name: g.PredecessorOrigin, Digest: map[string]string{"sha256": hex.EncodeToString(root)}}},
		PredicateType: PredicateLogGenesis,
		Predicate:     raw,
	}
	return ev, ev.Validate()
}

// EpochOrigin returns the origin of epoch k of a log whose epoch 1 has
// origin base: base itself for k = 1, base + "/e<k>" for k >= 2.
func EpochOrigin(base string, k int) string {
	if k <= 1 {
		return base
	}
	return base + "/e" + strconv.Itoa(k)
}

// ParseEpoch is the inverse of EpochOrigin: it returns k such that
// EpochOrigin(base, k) == origin, or an error.
func ParseEpoch(base, origin string) (int, error) {
	if base == "" {
		return 0, errors.New("event: empty base origin")
	}
	if origin == base {
		return 1, nil
	}
	rest, ok := strings.CutPrefix(origin, base+"/e")
	if !ok || rest == "" || rest[0] == '0' || strings.Trim(rest, "0123456789") != "" {
		return 0, fmt.Errorf("event: origin %q is not an epoch of %q", origin, base)
	}
	k, err := strconv.Atoi(rest)
	if err != nil || k < 2 {
		return 0, fmt.Errorf("event: origin %q is not an epoch of %q", origin, base)
	}
	return k, nil
}
