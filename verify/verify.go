// Package verify is what a client or auditor runs. It needs only the log
// directory (or one entry plus a proof) and public keys: nothing from the
// operator's infrastructure has to be trusted.
package verify

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/XtReL/trust-core/attest"
	"github.com/XtReL/trust-core/tlog"
	"github.com/XtReL/trust-core/tlog/filelog"
)

// Options configure a full-log verification.
type Options struct {
	Dir string
	// Origin pins the expected log identity; empty accepts the claimed one.
	Origin string
	// LogKey verifies checkpoint signatures (log operator key).
	LogKey ed25519.PublicKey
	// Attesters are the keys trusted to sign entries.
	Attesters []attest.Verifier
	// Previous is an earlier signed checkpoint the verifier kept. If set,
	// the log must still contain exactly the same first Previous.Size
	// entries: history was not rewritten.
	Previous []byte
}

// EntryResult describes one entry.
type EntryResult struct {
	Index         uint64   `json:"index"`
	OK            bool     `json:"ok"`
	KeyIDs        []string `json:"keyIds,omitempty"`
	PredicateType string   `json:"predicateType,omitempty"`
	Subjects      []string `json:"subjects,omitempty"`
	Error         string   `json:"error,omitempty"`
}

// Report is the verification outcome.
type Report struct {
	Origin       string        `json:"origin"`
	Size         uint64        `json:"size"`
	Root         string        `json:"root"`
	Entries      []EntryResult `json:"entries"`
	Uncommitted  uint64        `json:"uncommitted"`
	PreviousSize *uint64       `json:"previousSize,omitempty"`
	Problems     []string      `json:"problems,omitempty"`
	OK           bool          `json:"ok"`
}

// Log verifies a file-based log end to end:
//  1. the checkpoint is signed by the log key;
//  2. the entries on disk hash to the checkpoint root;
//  3. every entry is a DSSE envelope signed by a trusted attester and
//     carrying an in-toto Statement;
//  4. optionally, an earlier checkpoint is a prefix of the current log.
func Log(opts Options) (Report, error) {
	msg, err := os.ReadFile(filelog.CheckpointPath(opts.Dir))
	if err != nil {
		return Report{}, err
	}
	cp, err := tlog.OpenCheckpoint(msg, opts.Origin, opts.LogKey)
	if err != nil {
		return Report{}, fmt.Errorf("checkpoint: %w", err)
	}
	rep := Report{Origin: cp.Origin, Size: cp.Size, Root: base64.StdEncoding.EncodeToString(cp.Root[:])}

	leaves, err := filelog.LeafHashes(opts.Dir, cp.Size)
	if err != nil {
		rep.Problems = append(rep.Problems, err.Error())
		return rep, nil
	}
	if tlog.RootFromLeaves(leaves) != cp.Root {
		rep.Problems = append(rep.Problems, "entries on disk do not match the signed checkpoint root (log was modified)")
	}

	for i := uint64(0); i < cp.Size; i++ {
		rep.Entries = append(rep.Entries, checkEntry(opts.Dir, i, opts.Attesters))
		if !rep.Entries[i].OK {
			rep.Problems = append(rep.Problems, fmt.Sprintf("entry %d: %s", i, rep.Entries[i].Error))
		}
	}

	if files, err := filelog.CountEntryFiles(opts.Dir); err == nil && files > cp.Size {
		rep.Uncommitted = files - cp.Size
	}

	if len(opts.Previous) > 0 {
		prev, err := tlog.OpenCheckpoint(opts.Previous, cp.Origin, opts.LogKey)
		switch {
		case err != nil:
			rep.Problems = append(rep.Problems, "previous checkpoint: "+err.Error())
		case prev.Size > cp.Size:
			rep.Problems = append(rep.Problems, "log is smaller than the previous checkpoint (entries removed)")
		case tlog.RootFromLeaves(leaves[:prev.Size]) != prev.Root:
			rep.Problems = append(rep.Problems, "history was rewritten: first entries no longer match the previous checkpoint")
		default:
			s := prev.Size
			rep.PreviousSize = &s
		}
	}

	rep.OK = len(rep.Problems) == 0
	return rep, nil
}

func checkEntry(dir string, i uint64, attesters []attest.Verifier) EntryResult {
	res := EntryResult{Index: i}
	data, err := os.ReadFile(filelog.EntryPath(dir, i))
	if err != nil {
		res.Error = err.Error()
		return res
	}
	var env attest.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		res.Error = "not a DSSE envelope: " + err.Error()
		return res
	}
	if env.PayloadType != attest.PayloadType {
		res.Error = "unexpected payloadType " + env.PayloadType
		return res
	}
	payload, ids, err := attest.VerifyEnvelope(env, attesters)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	st, err := attest.ParseStatement(payload)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.OK, res.KeyIDs, res.PredicateType = true, ids, st.PredicateType
	for _, s := range st.Subject {
		res.Subjects = append(res.Subjects, s.Name)
	}
	return res
}

// Proof lets someone who holds a single entry check that it is in the log
// without downloading the rest of it.
type Proof struct {
	Index      uint64   `json:"index"`
	Size       uint64   `json:"size"`
	Path       []string `json:"path"`
	Checkpoint string   `json:"checkpoint"`
}

// Prove builds an inclusion proof for entry index against the current
// checkpoint of a file-based log.
func Prove(dir string, index uint64) (Proof, error) {
	msg, err := os.ReadFile(filelog.CheckpointPath(dir))
	if err != nil {
		return Proof{}, err
	}
	first, err := tlog.ParseCheckpoint(checkpointText(msg))
	if err != nil {
		return Proof{}, err
	}
	leaves, err := filelog.LeafHashes(dir, first.Size)
	if err != nil {
		return Proof{}, err
	}
	path, err := tlog.InclusionProof(leaves, index)
	if err != nil {
		return Proof{}, err
	}
	p := Proof{Index: index, Size: first.Size, Checkpoint: string(msg)}
	for _, h := range path {
		p.Path = append(p.Path, base64.StdEncoding.EncodeToString(h[:]))
	}
	return p, nil
}

func checkpointText(msg []byte) []byte {
	for i := 0; i+1 < len(msg); i++ {
		if msg[i] == '\n' && msg[i+1] == '\n' {
			return msg[:i+1]
		}
	}
	return msg
}

// Entry verifies one entry against a proof and the log key. It checks the
// checkpoint signature, the inclusion proof and, if attesters are given,
// the entry's own DSSE signature.
func Entry(entry []byte, p Proof, origin string, logKey ed25519.PublicKey, attesters []attest.Verifier) error {
	cp, err := tlog.OpenCheckpoint([]byte(p.Checkpoint), origin, logKey)
	if err != nil {
		return fmt.Errorf("checkpoint: %w", err)
	}
	if cp.Size != p.Size {
		return errors.New("proof size does not match the checkpoint")
	}
	var path []tlog.Hash
	for _, s := range p.Path {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil || len(b) != len(tlog.Hash{}) {
			return errors.New("malformed proof hash")
		}
		var h tlog.Hash
		copy(h[:], b)
		path = append(path, h)
	}
	if err := tlog.VerifyInclusion(tlog.LeafHash(entry), p.Index, p.Size, path, cp.Root); err != nil {
		return err
	}
	if len(attesters) > 0 {
		var env attest.Envelope
		if err := json.Unmarshal(entry, &env); err != nil {
			return err
		}
		if _, _, err := attest.VerifyEnvelope(env, attesters); err != nil {
			return err
		}
	}
	return nil
}
