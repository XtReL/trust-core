package verify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/XtReL/trust-core/attest"
	"github.com/XtReL/trust-core/event"
	"github.com/XtReL/trust-core/keys"
	"github.com/XtReL/trust-core/tlog"
	"github.com/XtReL/trust-core/tlog/filelog"
)

// Manifest is the verifier's own trusted description of a chain of log
// epochs (ADR 0002). Public keys come only from here, never from the
// repository being verified.
type Manifest struct {
	// Base is the origin of epoch 1; epoch k has origin
	// event.EpochOrigin(Base, k).
	Base   string          `json:"base"`
	Epochs []ManifestEpoch `json:"epochs"`
}

// ManifestEpoch describes one epoch. Paths are relative to the manifest
// file; LoadManifest resolves them.
type ManifestEpoch struct {
	Epoch int `json:"epoch"`
	// Log is the epoch's log directory.
	Log string `json:"log"`
	// PublicKey is the epoch's log key (PKIX PEM).
	PublicKey string `json:"publicKey"`
	// AttesterKeys are the keys trusted to sign entries. Empty means the
	// log key itself.
	AttesterKeys []string `json:"attesterKeys,omitempty"`
	// LastKnownCheckpoint is a checkpoint of this epoch the verifier kept
	// (as -previous for verify): it protects against a rollback.
	LastKnownCheckpoint string `json:"lastKnownCheckpoint,omitempty"`
	// AcceptUnplanned is the newKeyID of an unplanned rotation into this
	// epoch, after the verifier confirmed it with the owner out of band.
	AcceptUnplanned string `json:"acceptUnplanned,omitempty"`
}

// LoadManifest reads a manifest and resolves its paths relative to the
// manifest file.
func LoadManifest(path string) (Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("manifest %s: %w", path, err)
	}
	dir := filepath.Dir(path)
	rel := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(dir, p)
	}
	for i := range m.Epochs {
		e := &m.Epochs[i]
		e.Log, e.PublicKey, e.LastKnownCheckpoint = rel(e.Log), rel(e.PublicKey), rel(e.LastKnownCheckpoint)
		for j := range e.AttesterKeys {
			e.AttesterKeys[j] = rel(e.AttesterKeys[j])
		}
	}
	return m, nil
}

// EpochReport is the outcome for one epoch. For a frozen epoch (one that
// has a successor) Size and Root are those of the freeze checkpoint, which
// is authoritative; entries after it are listed as unconfirmed.
type EpochReport struct {
	Epoch  int    `json:"epoch"`
	Origin string `json:"origin"`
	Size   uint64 `json:"size"`
	Root   string `json:"root"`
	// Rotation is how this epoch was entered (empty for epoch 1).
	Rotation string `json:"rotation,omitempty"`
	Frozen   bool   `json:"frozen"`
	// Unconfirmed counts entries after the freeze point: present on disk
	// but not trusted. UnconfirmedEntries lists their indices.
	Unconfirmed        uint64   `json:"unconfirmed"`
	UnconfirmedEntries []uint64 `json:"unconfirmedEntries,omitempty"`
	Problems           []string `json:"problems,omitempty"`
	OK                 bool     `json:"ok"`
}

// ChainReport is the outcome of Chain.
type ChainReport struct {
	Base     string        `json:"base"`
	Epochs   []EpochReport `json:"epochs"`
	Problems []string      `json:"problems,omitempty"`
	OK       bool          `json:"ok"`
}

type epochKeys struct {
	log       ed25519.PublicKey
	attesters []attest.Verifier
	previous  []byte
}

func loadEpochKeys(e ManifestEpoch) (epochKeys, error) {
	var k epochKeys
	var err error
	if e.PublicKey == "" {
		return k, fmt.Errorf("manifest: epoch %d has no publicKey", e.Epoch)
	}
	if k.log, err = keys.LoadPublic(e.PublicKey); err != nil {
		return k, fmt.Errorf("manifest: epoch %d publicKey: %w", e.Epoch, err)
	}
	for _, p := range e.AttesterKeys {
		pub, err := keys.LoadPublic(p)
		if err != nil {
			return k, fmt.Errorf("manifest: epoch %d attesterKeys: %w", e.Epoch, err)
		}
		k.attesters = append(k.attesters, keys.NewVerifier(pub))
	}
	if e.LastKnownCheckpoint != "" {
		if k.previous, err = os.ReadFile(e.LastKnownCheckpoint); err != nil {
			return k, fmt.Errorf("manifest: epoch %d lastKnownCheckpoint: %w", e.Epoch, err)
		}
	}
	return k, nil
}

// Chain verifies a chain of log epochs described by the verifier's
// manifest (ADR 0002, sections 5 and 7):
//   - every epoch passes Log under its own key from the manifest, with its
//     lastKnownCheckpoint as Previous;
//   - entry 0 of every epoch k >= 2 is a genesis signed by the key of
//     epoch k that names epoch k-1, its key and a freeze checkpoint signed
//     by the key of epoch k-1, of which epoch k-1 on disk is an extension;
//   - a planned genesis is also signed by the key of epoch k-1, and epoch
//     k-1 did not grow after the freeze point;
//   - an unplanned genesis is accepted only if the manifest says so for
//     exactly its newKeyID; growth of epoch k-1 after the freeze point is
//     reported as unconfirmed.
//
// An error means the manifest itself is unusable (bad structure, missing
// key files); verification failures are reported in ChainReport.
func Chain(m Manifest) (ChainReport, error) {
	if m.Base == "" {
		return ChainReport{}, errors.New("manifest: base is required")
	}
	if len(m.Epochs) == 0 {
		return ChainReport{}, errors.New("manifest: no epochs")
	}
	ks := make([]epochKeys, len(m.Epochs))
	for i, e := range m.Epochs {
		if e.Epoch != i+1 {
			return ChainReport{}, fmt.Errorf("manifest: epochs must be listed as 1, 2, 3...; entry %d has epoch %d", i, e.Epoch)
		}
		if e.Log == "" {
			return ChainReport{}, fmt.Errorf("manifest: epoch %d has no log", e.Epoch)
		}
		if e.Epoch == 1 && e.AcceptUnplanned != "" {
			return ChainReport{}, errors.New("manifest: epoch 1 has no genesis; acceptUnplanned does not apply")
		}
		var err error
		if ks[i], err = loadEpochKeys(e); err != nil {
			return ChainReport{}, err
		}
	}

	rep := ChainReport{Base: m.Base}
	for i, e := range m.Epochs {
		rep.Epochs = append(rep.Epochs, checkEpoch(m.Base, e, ks[i]))
	}
	for i := 1; i < len(m.Epochs); i++ {
		checkLink(m.Base, m.Epochs[i-1], m.Epochs[i], ks[i-1], ks[i], &rep.Epochs[i-1], &rep.Epochs[i])
	}
	for i := range rep.Epochs {
		er := &rep.Epochs[i]
		er.OK = len(er.Problems) == 0
		for _, p := range er.Problems {
			rep.Problems = append(rep.Problems, fmt.Sprintf("epoch %d: %s", er.Epoch, p))
		}
	}
	rep.OK = len(rep.Problems) == 0
	return rep, nil
}

// checkEpoch runs the unchanged single-log verification on one epoch.
func checkEpoch(base string, e ManifestEpoch, k epochKeys) EpochReport {
	origin := event.EpochOrigin(base, e.Epoch)
	er := EpochReport{Epoch: e.Epoch, Origin: origin}
	attesters := k.attesters
	logVerifier := keys.NewVerifier(k.log)
	if e.Epoch >= 2 && len(k.attesters) > 0 {
		// The genesis (entry 0) is signed by the log key, which is not
		// necessarily an attester; it is checked below, and the log key
		// alone is not accepted for any other entry.
		attesters = append(append([]attest.Verifier{}, k.attesters...), logVerifier)
	} else if len(attesters) == 0 {
		attesters = []attest.Verifier{logVerifier}
	}
	lr, err := Log(Options{Dir: e.Log, Origin: origin, LogKey: k.log, Attesters: attesters, Previous: k.previous})
	if err != nil {
		er.Problems = append(er.Problems, err.Error())
		return er
	}
	er.Size, er.Root = lr.Size, lr.Root
	er.Problems = append(er.Problems, lr.Problems...)
	if e.Epoch >= 2 && len(k.attesters) > 0 {
		trusted := map[string]bool{}
		for _, v := range k.attesters {
			trusted[v.KeyID()] = true
		}
		for _, r := range lr.Entries {
			if r.Index == 0 || !r.OK {
				continue
			}
			ok := false
			for _, id := range r.KeyIDs {
				ok = ok || trusted[id]
			}
			if !ok {
				er.Problems = append(er.Problems, fmt.Sprintf("entry %d: not signed by a trusted attester", r.Index))
			}
		}
	}
	return er
}

// checkLink checks the genesis of epoch cur against epoch prev and
// applies the freeze point to prev's report.
func checkLink(base string, prev, cur ManifestEpoch, pk, ck epochKeys, pr, cr *EpochReport) {
	bad := func(format string, a ...any) { cr.Problems = append(cr.Problems, fmt.Sprintf(format, a...)) }

	data, err := os.ReadFile(filelog.EntryPath(cur.Log, 0))
	if err != nil {
		bad("entry 0 must be a log genesis: %v", err)
		return
	}
	var env attest.Envelope
	if err := json.Unmarshal(data, &env); err != nil || env.PayloadType != attest.PayloadType {
		bad("entry 0 must be a log genesis: not an in-toto DSSE envelope")
		return
	}
	payload, _, err := attest.VerifyEnvelope(env, []attest.Verifier{keys.NewVerifier(ck.log)})
	if err != nil {
		bad("genesis is not signed by the epoch %d key: %v", cur.Epoch, err)
		return
	}
	st, err := attest.ParseStatement(payload)
	if err != nil {
		bad("entry 0 must be a log genesis: %v", err)
		return
	}
	if st.PredicateType != event.PredicateLogGenesis {
		bad("entry 0 must be a log genesis, got predicateType %q", st.PredicateType)
		return
	}
	var g event.LogGenesis
	if err := json.Unmarshal(st.Predicate, &g); err != nil {
		bad("genesis predicate: %v", err)
		return
	}
	if err := g.Validate(); err != nil {
		bad("genesis predicate: %v", err)
		return
	}
	cr.Rotation = g.Rotation

	prevOrigin := event.EpochOrigin(base, prev.Epoch)
	if g.Epoch != cur.Epoch {
		bad("genesis epoch is %d, expected %d", g.Epoch, cur.Epoch)
	}
	if g.PredecessorOrigin != prevOrigin {
		bad("genesis predecessorOrigin is %q, expected %q", g.PredecessorOrigin, prevOrigin)
	}
	if g.PredecessorKeyID != keys.KeyID(pk.log) {
		bad("genesis predecessorKeyID %s is not the manifest key of epoch %d", g.PredecessorKeyID, prev.Epoch)
	}
	if g.NewKeyID != keys.KeyID(ck.log) {
		bad("genesis newKeyID %s is not the manifest key of epoch %d", g.NewKeyID, cur.Epoch)
	}

	root, _ := g.RootBytes()
	if len(st.Subject) != 1 || st.Subject[0].Name != g.PredecessorOrigin ||
		len(st.Subject[0].Digest) != 1 || st.Subject[0].Digest["sha256"] != hex.EncodeToString(root) {
		bad("genesis subject must be exactly the predecessor origin with sha256 = predecessorRoot")
	}

	switch g.Rotation {
	case event.RotationPlanned:
		if _, _, err := attest.VerifyEnvelope(env, []attest.Verifier{keys.NewVerifier(pk.log)}); err != nil {
			bad("planned rotation without a valid signature by the epoch %d key", prev.Epoch)
		}
	case event.RotationUnplanned:
		if cur.AcceptUnplanned == "" {
			bad("unplanned rotation to key %s is not accepted by the manifest (acceptUnplanned)", g.NewKeyID)
		} else if cur.AcceptUnplanned != g.NewKeyID {
			bad("unplanned rotation to key %s, but the manifest accepts %s", g.NewKeyID, cur.AcceptUnplanned)
		}
	}

	// The freeze checkpoint is authoritative for the previous epoch.
	fc, err := tlog.OpenCheckpoint([]byte(g.PredecessorCheckpoint), prevOrigin, pk.log)
	if err != nil {
		bad("genesis predecessorCheckpoint does not verify under the epoch %d key: %v", prev.Epoch, err)
		return
	}
	if fc.Size != g.PredecessorSize || !bytes.Equal(fc.Root[:], root) {
		bad("genesis predecessorSize/predecessorRoot do not match predecessorCheckpoint")
		return
	}
	freezeProblem := func(format string, a ...any) {
		pr.Problems = append(pr.Problems, fmt.Sprintf(format, a...))
	}
	pr.Frozen = true
	current := pr.Size
	pr.Size, pr.Root = fc.Size, base64.StdEncoding.EncodeToString(fc.Root[:])
	leaves, err := filelog.LeafHashes(prev.Log, fc.Size)
	if err != nil {
		freezeProblem("shorter than its freeze checkpoint: %v", err)
		return
	}
	if tlog.RootFromLeaves(leaves) != fc.Root {
		freezeProblem("history was rewritten before the freeze point: entries do not match the freeze checkpoint")
		return
	}
	if current < fc.Size {
		// Entries below the freeze point must all have been checked by Log.
		freezeProblem("current checkpoint (size %d) is behind the freeze checkpoint (size %d)", current, fc.Size)
	}
	files, err := filelog.CountEntryFiles(prev.Log)
	if err != nil {
		freezeProblem("%v", err)
		return
	}
	for i := fc.Size; i < files; i++ {
		pr.UnconfirmedEntries = append(pr.UnconfirmedEntries, i)
	}
	if files > fc.Size {
		pr.Unconfirmed = files - fc.Size
		if g.Rotation == event.RotationPlanned {
			freezeProblem("%d entries after the freeze point of a planned rotation (old key misuse)", pr.Unconfirmed)
		}
	}
}
