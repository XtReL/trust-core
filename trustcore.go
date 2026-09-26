// Package trustcore is the shared verifiable-evidence layer. A vertical
// builds an event.Event and calls Recorder.Record; Trust Core turns it into
// a signed in-toto attestation (DSSE) and appends it to a transparency log
// whose signed checkpoints anyone can verify with the public keys alone.
package trustcore

import (
	"encoding/hex"
	"encoding/json"

	"github.com/XtReL/trust-core/attest"
	"github.com/XtReL/trust-core/event"
	"github.com/XtReL/trust-core/tlog"
)

// Recorder signs events and appends them to a log.
type Recorder struct {
	// Attester signs the attestation (e.g. the CI job or scanner identity).
	Attester attest.Signer
	// Log stores the signed envelopes; its checkpoints are signed separately
	// by the log operator key.
	Log tlog.Log
}

// Receipt is what the caller keeps as proof of recording.
type Receipt struct {
	Index      uint64 `json:"index"`
	LeafHash   string `json:"leafHash"`
	Checkpoint string `json:"checkpoint"`
}

// Record validates, signs and logs one event.
func (r *Recorder) Record(ev event.Event) (Receipt, error) {
	st, err := attest.StatementFromEvent(ev)
	if err != nil {
		return Receipt{}, err
	}
	env, err := attest.SignStatement(st, r.Attester)
	if err != nil {
		return Receipt{}, err
	}
	entry, err := json.Marshal(env)
	if err != nil {
		return Receipt{}, err
	}
	index, err := r.Log.Append(entry)
	if err != nil {
		return Receipt{}, err
	}
	cp, err := r.Log.SignedCheckpoint()
	if err != nil {
		return Receipt{}, err
	}
	leaf := tlog.LeafHash(entry)
	return Receipt{Index: index, LeafHash: hex.EncodeToString(leaf[:]), Checkpoint: string(cp)}, nil
}
