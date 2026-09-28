// Package rotate starts a new log epoch signed by a new key (ADR 0002).
// The old epoch is never modified: it is frozen at a signed checkpoint,
// and entry 0 of the new epoch (the genesis) records that checkpoint.
//
//   - Planned: the old key is available. The freeze point is the current,
//     verified state of the old epoch; the genesis is signed by both keys.
//   - Unplanned: the old key is lost or compromised. The freeze point is a
//     checkpoint the owner or an auditor kept (the old log may have been
//     altered); the genesis is signed by the new key only, and verifiers
//     must accept the new key explicitly.
package rotate

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/XtReL/trust-core/attest"
	"github.com/XtReL/trust-core/event"
	"github.com/XtReL/trust-core/keys"
	"github.com/XtReL/trust-core/tlog"
	"github.com/XtReL/trust-core/tlog/filelog"
	"github.com/XtReL/trust-core/verify"
)

// Result describes the new epoch.
type Result struct {
	Epoch    int    `json:"epoch"`
	Origin   string `json:"origin"`
	NewKeyID string `json:"newKeyID"`
	// VerifierKey is the note verifier key (vkey) of the new epoch.
	VerifierKey string `json:"verifierKey"`
	FrozenSize  uint64 `json:"frozenSize"`
	// AfterFreeze counts old-epoch entry files beyond the freeze point.
	// They are ignored (unplanned only; a planned rotation refuses them).
	AfterFreeze uint64 `json:"afterFreeze"`
}

// nextEpoch derives the base origin and the next epoch number from the
// origin of the epoch being rotated: a "/e<k>" suffix means epoch k, else 1.
func nextEpoch(fromOrigin string) (base string, next int) {
	if i := strings.LastIndex(fromOrigin, "/e"); i > 0 {
		if k, err := event.ParseEpoch(fromOrigin[:i], fromOrigin); err == nil && k >= 2 {
			return fromOrigin[:i], k + 1
		}
	}
	return fromOrigin, 2
}

// Planned freezes the old epoch at its current checkpoint and starts the
// next epoch in to, with a genesis signed by both keys.
func Planned(from, fromOrigin string, oldSigner *keys.Signer, to string, newSigner *keys.Signer, note string) (Result, error) {
	if oldSigner == nil || newSigner == nil {
		return Result{}, errors.New("rotate: both the old and the new key are required")
	}
	msg, err := os.ReadFile(filelog.CheckpointPath(from))
	if err != nil {
		return Result{}, err
	}
	cp, err := freeze(from, fromOrigin, oldSigner.Public(), msg)
	if err != nil {
		return Result{}, err
	}
	files, err := filelog.CountEntryFiles(from)
	if err != nil {
		return Result{}, err
	}
	if files > cp.Size {
		return Result{}, fmt.Errorf("rotate: %d uncommitted entry file(s) after the checkpoint in %s; resolve them before a planned rotation", files-cp.Size, from)
	}
	return start(from, fromOrigin, oldSigner.Public(), cp, msg, event.RotationPlanned, to, newSigner, oldSigner, note, 0)
}

// Unplanned freezes the old epoch at trustedCheckpoint, a checkpoint kept
// outside the old log, and starts the next epoch in to, with a genesis
// signed by the new key only. Old-epoch entries after the freeze point are
// ignored.
func Unplanned(from, fromOrigin string, oldPub ed25519.PublicKey, trustedCheckpoint []byte, to string, newSigner *keys.Signer, note string) (Result, error) {
	if newSigner == nil {
		return Result{}, errors.New("rotate: the new key is required")
	}
	if len(trustedCheckpoint) == 0 {
		return Result{}, errors.New("rotate: an unplanned rotation requires a trusted checkpoint")
	}
	cp, err := freeze(from, fromOrigin, oldPub, trustedCheckpoint)
	if err != nil {
		return Result{}, err
	}
	files, err := filelog.CountEntryFiles(from)
	if err != nil {
		return Result{}, err
	}
	return start(from, fromOrigin, oldPub, cp, trustedCheckpoint, event.RotationUnplanned, to, newSigner, nil, note, files-cp.Size)
}

// freeze verifies the freeze checkpoint under the old key and origin and
// checks that the first Size entries of the old epoch hash to its root.
func freeze(from, fromOrigin string, oldPub ed25519.PublicKey, msg []byte) (tlog.Checkpoint, error) {
	cp, err := tlog.OpenCheckpoint(msg, fromOrigin, oldPub)
	if err != nil {
		return tlog.Checkpoint{}, fmt.Errorf("rotate: freeze checkpoint: %w", err)
	}
	leaves, err := filelog.LeafHashes(from, cp.Size)
	if err != nil {
		return tlog.Checkpoint{}, fmt.Errorf("rotate: old epoch is shorter than the freeze checkpoint: %w", err)
	}
	if tlog.RootFromLeaves(leaves) != cp.Root {
		return tlog.Checkpoint{}, errors.New("rotate: history was rewritten before the freeze point: old epoch entries do not match the freeze checkpoint")
	}
	return cp, nil
}

func start(from, fromOrigin string, oldPub ed25519.PublicKey, cp tlog.Checkpoint, cpMsg []byte, rotation, to string, newSigner, oldSigner *keys.Signer, note string, afterFreeze uint64) (Result, error) {
	newPub := newSigner.Public()
	if newPub.Equal(oldPub) {
		return Result{}, errors.New("rotate: the new key equals the old key")
	}
	if filepath.Clean(from) == filepath.Clean(to) {
		return Result{}, errors.New("rotate: the new epoch must go to a different directory")
	}
	base, k := nextEpoch(fromOrigin)
	origin := event.EpochOrigin(base, k)
	ev, err := event.NewLogGenesis(event.LogGenesis{
		Epoch:                 k,
		PredecessorOrigin:     fromOrigin,
		PredecessorSize:       cp.Size,
		PredecessorRoot:       base64.StdEncoding.EncodeToString(cp.Root[:]),
		PredecessorCheckpoint: string(cpMsg),
		PredecessorKeyID:      keys.KeyID(oldPub),
		NewKeyID:              keys.KeyID(newPub),
		Rotation:              rotation,
		Note:                  note,
	})
	if err != nil {
		return Result{}, err
	}
	st, err := attest.StatementFromEvent(ev)
	if err != nil {
		return Result{}, err
	}
	signers := []attest.Signer{newSigner}
	if oldSigner != nil {
		signers = append(signers, oldSigner)
	}
	env, err := attest.SignStatement(st, signers...)
	if err != nil {
		return Result{}, err
	}
	entry, err := json.Marshal(env)
	if err != nil {
		return Result{}, err
	}

	l, err := filelog.Init(to, origin, newSigner)
	if err != nil {
		return Result{}, err
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(filelog.EntryPath(to, 0)), ".gitkeep"), nil, 0o644); err != nil {
		return Result{}, err
	}
	if _, err := l.Append(entry); err != nil {
		return Result{}, err
	}
	rep, err := verify.Log(verify.Options{Dir: to, Origin: origin, LogKey: newPub,
		Attesters: []attest.Verifier{keys.NewVerifier(newPub)}})
	if err != nil {
		return Result{}, fmt.Errorf("rotate: new epoch does not verify: %w", err)
	}
	if !rep.OK {
		return Result{}, fmt.Errorf("rotate: new epoch does not verify: %s", strings.Join(rep.Problems, "; "))
	}
	return Result{Epoch: k, Origin: origin, NewKeyID: keys.KeyID(newPub),
		VerifierKey: tlog.VerifierKey(origin, newPub), FrozenSize: cp.Size, AfterFreeze: afterFreeze}, nil
}
