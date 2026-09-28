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
// is authoritative; the current checkpoint file and entries after the
// freeze point are reported for information only (ADR 0002, section 5).
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
	// CurrentSize is the size of the epoch's current checkpoint file, set
	// for a frozen epoch when that file verifies. It does not affect the
	// verdict.
	CurrentSize *uint64 `json:"currentSize,omitempty"`
	// Notes are informational findings that do not affect the verdict.
	Notes    []string `json:"notes,omitempty"`
	Problems []string `json:"problems,omitempty"`
	OK       bool     `json:"ok"`
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
//   - entry 0 of every epoch k >= 2 is a genesis signed by the key of
//     epoch k that names epoch k-1, its key and a freeze checkpoint signed
//     by the key of epoch k-1;
//   - a planned genesis is also signed by the key of epoch k-1; an
//     unplanned one is accepted only if the manifest says so for exactly
//     its newKeyID;
//   - the last epoch passes Log under its own key from the manifest, with
//     its lastKnownCheckpoint as Previous;
//   - a frozen epoch is verified against its freeze checkpoint only: its
//     first N entries hash to the frozen root and are signed by trusted
//     attesters, and lastKnownCheckpoint is a prefix of that state. Its
//     current checkpoint file and entries after N are only reported
//     (unconfirmed); after a planned rotation such entries are an error.
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

	// links[i] is the genesis of epoch i+1, linking it to epoch i.
	links := make([]link, len(m.Epochs))
	for i := 1; i < len(m.Epochs); i++ {
		links[i] = checkGenesis(m.Base, m.Epochs[i-1], m.Epochs[i], ks[i-1], ks[i])
	}
	rep := ChainReport{Base: m.Base}
	for i, e := range m.Epochs {
		var er EpochReport
		if i+1 < len(m.Epochs) && links[i+1].freeze != nil {
			er = checkFrozen(m.Base, e, ks[i], *links[i+1].freeze, links[i+1].rotation)
		} else {
			// The last epoch, or one whose successor has no usable
			// freeze checkpoint (the successor fails in that case).
			er = checkEpoch(m.Base, e, ks[i])
		}
		er.Rotation = links[i].rotation
		er.Problems = append(er.Problems, links[i].problems...)
		er.OK = len(er.Problems) == 0
		for _, p := range er.Problems {
			rep.Problems = append(rep.Problems, fmt.Sprintf("epoch %d: %s", er.Epoch, p))
		}
		rep.Epochs = append(rep.Epochs, er)
	}
	rep.OK = len(rep.Problems) == 0
	return rep, nil
}

// epochAttesters returns the keys accepted for entry signatures by Log or
// checkFrozen. The genesis (entry 0 of epoch k >= 2) is signed by the log
// key, which is not necessarily an attester: it is added here and
// attesterProblems rejects it for every other entry.
func epochAttesters(e ManifestEpoch, k epochKeys) []attest.Verifier {
	logVerifier := keys.NewVerifier(k.log)
	switch {
	case len(k.attesters) == 0:
		return []attest.Verifier{logVerifier}
	case e.Epoch >= 2:
		return append(append([]attest.Verifier{}, k.attesters...), logVerifier)
	default:
		return k.attesters
	}
}

func attesterProblems(e ManifestEpoch, k epochKeys, entries []EntryResult) []string {
	if e.Epoch < 2 || len(k.attesters) == 0 {
		return nil
	}
	trusted := map[string]bool{}
	for _, v := range k.attesters {
		trusted[v.KeyID()] = true
	}
	var out []string
	for _, r := range entries {
		if r.Index == 0 || !r.OK {
			continue
		}
		ok := false
		for _, id := range r.KeyIDs {
			ok = ok || trusted[id]
		}
		if !ok {
			out = append(out, fmt.Sprintf("entry %d: not signed by a trusted attester", r.Index))
		}
	}
	return out
}

// checkEpoch runs the unchanged single-log verification on a live epoch.
func checkEpoch(base string, e ManifestEpoch, k epochKeys) EpochReport {
	origin := event.EpochOrigin(base, e.Epoch)
	er := EpochReport{Epoch: e.Epoch, Origin: origin}
	lr, err := Log(Options{Dir: e.Log, Origin: origin, LogKey: k.log, Attesters: epochAttesters(e, k), Previous: k.previous})
	if err != nil {
		er.Problems = append(er.Problems, err.Error())
		return er
	}
	er.Size, er.Root = lr.Size, lr.Root
	er.Problems = append(er.Problems, lr.Problems...)
	er.Problems = append(er.Problems, attesterProblems(e, k, lr.Entries)...)
	return er
}

// checkFrozen verifies an epoch that has a successor against the freeze
// checkpoint from the successor's genesis. The epoch's current checkpoint
// file is not trusted: after an unplanned rotation whoever holds the old
// key controls it, so it is only reported.
func checkFrozen(base string, e ManifestEpoch, k epochKeys, fc tlog.Checkpoint, rotation string) EpochReport {
	origin := event.EpochOrigin(base, e.Epoch)
	er := EpochReport{Epoch: e.Epoch, Origin: origin, Frozen: true,
		Size: fc.Size, Root: base64.StdEncoding.EncodeToString(fc.Root[:])}
	bad := func(format string, a ...any) { er.Problems = append(er.Problems, fmt.Sprintf(format, a...)) }
	note := func(format string, a ...any) { er.Notes = append(er.Notes, fmt.Sprintf(format, a...)) }

	// Informational: the current checkpoint file.
	if msg, err := os.ReadFile(filelog.CheckpointPath(e.Log)); err != nil {
		note("current checkpoint: %v", err)
	} else if cur, err := tlog.OpenCheckpoint(msg, origin, k.log); err != nil {
		note("current checkpoint does not verify (ignored for a frozen epoch): %v", err)
	} else {
		size := cur.Size
		er.CurrentSize = &size
		if cur.Size < fc.Size {
			note("current checkpoint (size %d) is behind the freeze checkpoint (size %d) (ignored for a frozen epoch)", cur.Size, fc.Size)
		}
	}

	// Entries after the freeze point: unconfirmed.
	if files, err := filelog.CountEntryFiles(e.Log); err != nil {
		bad("%v", err)
	} else if files > fc.Size {
		for i := fc.Size; i < files; i++ {
			er.UnconfirmedEntries = append(er.UnconfirmedEntries, i)
		}
		er.Unconfirmed = files - fc.Size
		if rotation == event.RotationPlanned {
			bad("%d entries after the freeze point of a planned rotation (old key misuse)", er.Unconfirmed)
		}
	}

	// Entries [0, N): the frozen root and every entry signature.
	leaves, err := filelog.LeafHashes(e.Log, fc.Size)
	if err != nil {
		bad("shorter than its freeze checkpoint: %v", err)
		return er
	}
	if tlog.RootFromLeaves(leaves) != fc.Root {
		bad("history was rewritten before the freeze point: entries do not match the freeze checkpoint")
	}
	attesters := epochAttesters(e, k)
	var entries []EntryResult
	for i := uint64(0); i < fc.Size; i++ {
		r := checkEntry(e.Log, i, attesters)
		if !r.OK {
			bad("entry %d: %s", i, r.Error)
		}
		entries = append(entries, r)
	}
	er.Problems = append(er.Problems, attesterProblems(e, k, entries)...)

	// The verifier's own checkpoint must be a prefix of the frozen state.
	if len(k.previous) > 0 {
		prev, err := tlog.OpenCheckpoint(k.previous, origin, k.log)
		switch {
		case err != nil:
			bad("lastKnownCheckpoint: %v", err)
		case prev.Size > fc.Size && rotation == event.RotationUnplanned:
			bad("lastKnownCheckpoint (size %d) is beyond the freeze point (size %d) of an unplanned rotation: the trusted checkpoint used for the rotation is older than what this verifier saw; a human decision is needed", prev.Size, fc.Size)
		case prev.Size > fc.Size:
			bad("lastKnownCheckpoint (size %d) is beyond the freeze point (size %d)", prev.Size, fc.Size)
		case tlog.RootFromLeaves(leaves[:prev.Size]) != prev.Root:
			bad("history was rewritten: first entries no longer match lastKnownCheckpoint")
		}
	}
	return er
}

// link is the outcome of checking the genesis of one epoch.
type link struct {
	rotation string
	// freeze is the verified freeze checkpoint of the previous epoch, or
	// nil if the genesis does not provide one.
	freeze   *tlog.Checkpoint
	problems []string
}

// checkGenesis checks entry 0 of epoch cur against epoch prev.
func checkGenesis(base string, prev, cur ManifestEpoch, pk, ck epochKeys) (l link) {
	bad := func(format string, a ...any) { l.problems = append(l.problems, fmt.Sprintf(format, a...)) }

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
	l.rotation = g.Rotation

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

	fc, err := tlog.OpenCheckpoint([]byte(g.PredecessorCheckpoint), prevOrigin, pk.log)
	if err != nil {
		bad("genesis predecessorCheckpoint does not verify under the epoch %d key: %v", prev.Epoch, err)
		return
	}
	if fc.Size != g.PredecessorSize || !bytes.Equal(fc.Root[:], root) {
		bad("genesis predecessorSize/predecessorRoot do not match predecessorCheckpoint")
		return
	}
	l.freeze = &fc
	return
}
