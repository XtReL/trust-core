package verify_test

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	trustcore "github.com/XtReL/trust-core"
	"github.com/XtReL/trust-core/attest"
	"github.com/XtReL/trust-core/event"
	"github.com/XtReL/trust-core/keys"
	"github.com/XtReL/trust-core/rotate"
	"github.com/XtReL/trust-core/tlog/filelog"
	"github.com/XtReL/trust-core/verify"
)

const base = "trust.example.com/test/evidence"

// chainFixture keeps every file under one directory, so the manifest can
// use relative paths as a verifier's would.
type chainFixture struct {
	t    *testing.T
	root string
	keys []*keys.Signer // keys[k-1] is the key of epoch k
}

func newChain(t *testing.T, entries int) *chainFixture {
	t.Helper()
	c := &chainFixture{t: t, root: t.TempDir()}
	k := c.newKey()
	if _, err := filelog.Init(c.dir(1), base, k); err != nil {
		t.Fatal(err)
	}
	c.keys = append(c.keys, k)
	c.record(1, entries)
	return c
}

func (c *chainFixture) newKey() *keys.Signer {
	_, priv, err := keys.Generate()
	if err != nil {
		c.t.Fatal(err)
	}
	return keys.NewSigner(priv)
}

func (c *chainFixture) dir(k int) string { return filepath.Join(c.root, "ev-e"+string(rune('0'+k))) }

func (c *chainFixture) origin(k int) string { return event.EpochOrigin(base, k) }

// record appends n test results to epoch k under the epoch key, signed by
// attester (default: the epoch key itself, as in Gatekeeper).
func (c *chainFixture) record(k, n int, attester ...*keys.Signer) {
	c.t.Helper()
	s := c.keys[k-1]
	if len(attester) > 0 {
		s = attester[0]
	}
	l, err := filelog.Open(c.dir(k), c.origin(k), c.keys[k-1])
	if err != nil {
		c.t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		ev, err := event.NewTestResult(
			[]event.Subject{{Name: "repo", Digest: map[string]string{"gitCommit": strings.Repeat("ab", 20)}}},
			event.TestResult{Result: event.ResultPassed, Configuration: []event.ResourceDescriptor{{Name: "rules"}}},
		)
		if err != nil {
			c.t.Fatal(err)
		}
		if _, err := (&trustcore.Recorder{Attester: s, Log: l}).Record(ev); err != nil {
			c.t.Fatal(err)
		}
	}
}

func (c *chainFixture) checkpoint(k int) []byte {
	msg, err := os.ReadFile(filelog.CheckpointPath(c.dir(k)))
	if err != nil {
		c.t.Fatal(err)
	}
	return msg
}

func (c *chainFixture) planned() rotate.Result {
	c.t.Helper()
	k := len(c.keys)
	nk := c.newKey()
	res, err := rotate.Planned(c.dir(k), c.origin(k), c.keys[k-1], c.dir(k+1), nk, "")
	if err != nil {
		c.t.Fatal(err)
	}
	c.keys = append(c.keys, nk)
	return res
}

func (c *chainFixture) unplanned(trusted []byte) rotate.Result {
	c.t.Helper()
	k := len(c.keys)
	nk := c.newKey()
	res, err := rotate.Unplanned(c.dir(k), c.origin(k), c.keys[k-1].Public(), trusted, c.dir(k+1), nk, "device lost")
	if err != nil {
		c.t.Fatal(err)
	}
	c.keys = append(c.keys, nk)
	return res
}

// manifest writes the verifier's public keys and a manifest.json with
// relative paths, lets edit adjust the epochs, and loads it back.
func (c *chainFixture) manifest(edit func([]map[string]any)) verify.Manifest {
	c.t.Helper()
	os.MkdirAll(filepath.Join(c.root, "keys"), 0o755)
	var epochs []map[string]any
	for i, k := range c.keys {
		pub := filepath.Join("keys", "e"+string(rune('1'+i))+".pub")
		if err := keys.WritePublic(filepath.Join(c.root, pub), k.Public()); err != nil {
			c.t.Fatal(err)
		}
		epochs = append(epochs, map[string]any{"epoch": i + 1, "log": filepath.Base(c.dir(i + 1)), "publicKey": pub})
	}
	if edit != nil {
		edit(epochs)
	}
	raw, _ := json.Marshal(map[string]any{"base": base, "epochs": epochs})
	path := filepath.Join(c.root, "manifest.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		c.t.Fatal(err)
	}
	m, err := verify.LoadManifest(path)
	if err != nil {
		c.t.Fatal(err)
	}
	return m
}

// writeFile stores data under the fixture root and returns its relative path.
func (c *chainFixture) writeFile(name string, data []byte) string {
	if err := os.WriteFile(filepath.Join(c.root, name), data, 0o644); err != nil {
		c.t.Fatal(err)
	}
	return name
}

func chain(t *testing.T, m verify.Manifest) verify.ChainReport {
	t.Helper()
	rep, err := verify.Chain(m)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func expectOK(t *testing.T, rep verify.ChainReport) {
	t.Helper()
	if !rep.OK {
		t.Fatalf("expected a valid chain, problems: %q", rep.Problems)
	}
}

func expectFail(t *testing.T, rep verify.ChainReport, want string) {
	t.Helper()
	if rep.OK {
		t.Fatalf("expected a failure containing %q", want)
	}
	for _, p := range rep.Problems {
		if strings.Contains(p, want) {
			return
		}
	}
	t.Fatalf("no problem contains %q: %q", want, rep.Problems)
}

// Task test 1.
func TestChainPlannedThreeEpochs(t *testing.T) {
	c := newChain(t, 3)
	kept1 := c.writeFile("cp-e1", c.checkpoint(1))
	c.planned()
	c.record(2, 2)
	c.planned()
	c.record(3, 1)
	kept3 := c.writeFile("cp-e3", c.checkpoint(3))
	c.record(3, 1)

	rep := chain(t, c.manifest(func(e []map[string]any) {
		e[0]["lastKnownCheckpoint"] = kept1
		e[2]["lastKnownCheckpoint"] = kept3
	}))
	expectOK(t, rep)
	want := []struct {
		size     uint64
		rotation string
		frozen   bool
	}{{3, "", true}, {3, event.RotationPlanned, true}, {3, event.RotationPlanned, false}}
	for i, w := range want {
		e := rep.Epochs[i]
		if e.Epoch != i+1 || e.Origin != c.origin(i+1) || e.Size != w.size || e.Rotation != w.rotation || e.Frozen != w.frozen || e.Unconfirmed != 0 {
			t.Fatalf("epoch %d: %+v", i+1, e)
		}
	}
	// The same checks through the JSON report.
	raw, _ := json.Marshal(rep)
	if !strings.Contains(string(raw), `"ok":true`) || !strings.Contains(string(raw), `"rotation":"planned"`) {
		t.Fatalf("JSON report: %s", raw)
	}
}

// Task test 2.
func TestChainUnplannedNeedsExplicitAcceptance(t *testing.T) {
	c := newChain(t, 3)
	res := c.unplanned(c.checkpoint(1))
	c.record(2, 1)

	expectFail(t, chain(t, c.manifest(nil)), "not accepted by the manifest")
	expectFail(t, chain(t, c.manifest(func(e []map[string]any) {
		e[1]["acceptUnplanned"] = keys.KeyID(c.newKey().Public())
	})), "but the manifest accepts")
	rep := chain(t, c.manifest(func(e []map[string]any) { e[1]["acceptUnplanned"] = res.NewKeyID }))
	expectOK(t, rep)
	if rep.Epochs[1].Rotation != event.RotationUnplanned {
		t.Fatalf("rotation: %+v", rep.Epochs[1])
	}
}

// Task test 3: after the freeze point, entries signed by the old key are
// appended to the old epoch.
func TestChainCompromisedOldKey(t *testing.T) {
	t.Run("unplanned", func(t *testing.T) {
		c := newChain(t, 3)
		kept := c.checkpoint(1)
		c.record(1, 1) // the attacker already wrote before the rotation...
		res := c.unplanned(kept)
		c.record(1, 2) // ...and keeps writing after it
		rep := chain(t, c.manifest(func(e []map[string]any) { e[1]["acceptUnplanned"] = res.NewKeyID }))
		expectOK(t, rep)
		e1 := rep.Epochs[0]
		if e1.Size != 3 || !e1.Frozen || e1.Unconfirmed != 3 || len(e1.UnconfirmedEntries) != 3 || e1.UnconfirmedEntries[0] != 3 {
			t.Fatalf("epoch 1: %+v", e1)
		}
	})
	t.Run("planned", func(t *testing.T) {
		c := newChain(t, 3)
		c.planned()
		c.record(1, 2, c.keys[0])
		rep := chain(t, c.manifest(nil))
		expectFail(t, rep, "after the freeze point of a planned rotation")
		if rep.Epochs[0].Unconfirmed != 2 {
			t.Fatalf("epoch 1: %+v", rep.Epochs[0])
		}
	})
}

// writeEpoch creates epoch k by hand with entry 0 signed by signers.
func (c *chainFixture) writeEpoch(k int, ev event.Event, signers ...attest.Signer) {
	c.t.Helper()
	nk := c.newKey()
	l, err := filelog.Init(c.dir(k), c.origin(k), nk)
	if err != nil {
		c.t.Fatal(err)
	}
	st, err := attest.StatementFromEvent(ev)
	if err != nil {
		c.t.Fatal(err)
	}
	if len(signers) == 0 {
		signers = []attest.Signer{nk}
	}
	env, err := attest.SignStatement(st, signers...)
	if err != nil {
		c.t.Fatal(err)
	}
	raw, _ := json.Marshal(env)
	if _, err := l.Append(raw); err != nil {
		c.t.Fatal(err)
	}
	c.keys = append(c.keys, nk)
}

// genesis returns a genesis for epoch 2 of c, as rotate would build it.
func (c *chainFixture) genesis(newKey *keys.Signer, rotation string) event.LogGenesis {
	cpMsg := c.checkpoint(1)
	cp := strings.Split(string(cpMsg), "\n")
	var size uint64
	json.Unmarshal([]byte(cp[1]), &size)
	return event.LogGenesis{
		Epoch: 2, PredecessorOrigin: c.origin(1), PredecessorSize: size, PredecessorRoot: cp[2],
		PredecessorCheckpoint: string(cpMsg), PredecessorKeyID: c.keys[0].KeyID(), NewKeyID: newKey.KeyID(),
		Rotation: rotation,
	}
}

// writeGenesisEpoch creates epoch 2 with a genesis edited by mut and
// signed by the new key plus extra signers.
func (c *chainFixture) writeGenesisEpoch(rotation string, mut func(*event.LogGenesis), extra ...attest.Signer) {
	c.t.Helper()
	nk := c.newKey()
	g := c.genesis(nk, rotation)
	if mut != nil {
		mut(&g)
	}
	ev, err := event.NewLogGenesis(g)
	if err != nil {
		c.t.Fatal(err)
	}
	l, err := filelog.Init(c.dir(2), c.origin(2), nk)
	if err != nil {
		c.t.Fatal(err)
	}
	st, _ := attest.StatementFromEvent(ev)
	env, err := attest.SignStatement(st, append([]attest.Signer{nk}, extra...)...)
	if err != nil {
		c.t.Fatal(err)
	}
	raw, _ := json.Marshal(env)
	if _, err := l.Append(raw); err != nil {
		c.t.Fatal(err)
	}
	c.keys = append(c.keys, nk)
}

// Task test 5: a planned genesis signed by the new key only is refused and
// not downgraded to unplanned, even if the manifest would accept that.
func TestChainPlannedWithoutOldSignature(t *testing.T) {
	c := newChain(t, 2)
	c.writeGenesisEpoch(event.RotationPlanned, nil)
	rep := chain(t, c.manifest(func(e []map[string]any) { e[1]["acceptUnplanned"] = c.keys[1].KeyID() }))
	expectFail(t, rep, "planned rotation without a valid signature")

	// The reference: the same genesis signed by both keys passes.
	c = newChain(t, 2)
	c.writeGenesisEpoch(event.RotationPlanned, nil, c.keys[0])
	expectOK(t, chain(t, c.manifest(nil)))
}

// Task test 6.
func TestChainEntryZeroMustBeTheRightGenesis(t *testing.T) {
	t.Run("not a genesis", func(t *testing.T) {
		c := newChain(t, 2)
		ev, _ := event.NewTestResult(
			[]event.Subject{{Name: "repo", Digest: map[string]string{"gitCommit": strings.Repeat("cd", 20)}}},
			event.TestResult{Result: event.ResultPassed, Configuration: []event.ResourceDescriptor{{Name: "rules"}}},
		)
		c.writeEpoch(2, ev)
		expectFail(t, chain(t, c.manifest(nil)), "entry 0 must be a log genesis")
	})
	t.Run("empty epoch", func(t *testing.T) {
		c := newChain(t, 2)
		nk := c.newKey()
		filelog.Init(c.dir(2), c.origin(2), nk)
		c.keys = append(c.keys, nk)
		expectFail(t, chain(t, c.manifest(nil)), "entry 0 must be a log genesis")
	})
	cases := map[string]struct {
		mut  func(*event.LogGenesis)
		want string
	}{
		"wrong epoch":  {func(g *event.LogGenesis) { g.Epoch = 3 }, "genesis epoch is 3"},
		"wrong origin": {func(g *event.LogGenesis) { g.PredecessorOrigin = base + "/e5" }, "predecessorOrigin"},
		"wrong size": {func(g *event.LogGenesis) { g.PredecessorSize = 1 },
			"do not match predecessorCheckpoint"},
		"wrong root": {func(g *event.LogGenesis) {
			g.PredecessorRoot = base64.StdEncoding.EncodeToString(make([]byte, 32))
		}, "do not match predecessorCheckpoint"},
		"foreign predecessor key": {func(g *event.LogGenesis) { g.PredecessorKeyID = strings.Repeat("0", 64) },
			"predecessorKeyID"},
		"foreign new key": {func(g *event.LogGenesis) { g.NewKeyID = strings.Repeat("1", 64) },
			"newKeyID"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := newChain(t, 2)
			c.writeGenesisEpoch(event.RotationPlanned, tc.mut, c.keys[0])
			expectFail(t, chain(t, c.manifest(nil)), tc.want)
		})
	}
	t.Run("predecessor checkpoint of another log", func(t *testing.T) {
		c := newChain(t, 2)
		other := newChain(t, 2)
		c.writeGenesisEpoch(event.RotationPlanned, func(g *event.LogGenesis) {
			g.PredecessorCheckpoint = string(other.checkpoint(1))
		}, c.keys[0])
		expectFail(t, chain(t, c.manifest(nil)), "predecessorCheckpoint does not verify")
	})
	t.Run("predecessor rewritten before freeze", func(t *testing.T) {
		c := newChain(t, 2)
		c.planned()
		os.WriteFile(filelog.EntryPath(c.dir(1), 1), []byte(`{"forged":true}`), 0o644)
		expectFail(t, chain(t, c.manifest(nil)), "rewritten before the freeze point")
	})
}

// Task test 7: the verifier's manifest names another key for epoch 2 than
// the one the genesis (and the epoch) is signed with.
func TestChainKeySubstitution(t *testing.T) {
	c := newChain(t, 2)
	c.planned()
	c.record(2, 1)
	c.keys[1] = c.newKey()
	rep := chain(t, c.manifest(nil))
	expectFail(t, rep, "genesis is not signed by the epoch 2 key")
	expectFail(t, rep, "checkpoint")

	// An attacker with its own key forges epoch 2 claiming a planned
	// rotation; the manifest keeps the real key for epoch 1 only.
	c = newChain(t, 2)
	c.writeGenesisEpoch(event.RotationPlanned, nil) // no old-key signature possible
	expectFail(t, chain(t, c.manifest(nil)), "planned rotation without a valid signature")
}

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.Create(target)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Task test 8: the verifier kept a newer checkpoint than the log it is
// shown (the chain was rolled back to earlier history).
func TestChainRollback(t *testing.T) {
	c := newChain(t, 2)
	c.planned()
	c.record(2, 1)
	copyDir(t, c.dir(2), filepath.Join(c.root, "old-e2"))
	c.record(2, 2)
	kept := c.writeFile("cp-e2", c.checkpoint(2))
	os.RemoveAll(c.dir(2))
	copyDir(t, filepath.Join(c.root, "old-e2"), c.dir(2))

	expectOK(t, chain(t, c.manifest(nil)))
	expectFail(t, chain(t, c.manifest(func(e []map[string]any) { e[1]["lastKnownCheckpoint"] = kept })),
		"smaller than the previous checkpoint")
}

// A separate attester key: the epoch key signs the genesis only.
func TestChainSeparateAttesters(t *testing.T) {
	c := newChain(t, 0)
	att := c.newKey()
	c.record(1, 2, att)
	c.planned()
	l, _ := filelog.Open(c.dir(2), c.origin(2), c.keys[1])
	ev, _ := event.NewTestResult(
		[]event.Subject{{Name: "repo", Digest: map[string]string{"gitCommit": strings.Repeat("ef", 20)}}},
		event.TestResult{Result: event.ResultPassed, Configuration: []event.ResourceDescriptor{{Name: "rules"}}},
	)
	if _, err := (&trustcore.Recorder{Attester: att, Log: l}).Record(ev); err != nil {
		t.Fatal(err)
	}
	keys.WritePublic(filepath.Join(c.root, "att.pub"), att.Public())
	withAtt := func(e []map[string]any) {
		e[0]["attesterKeys"] = []string{"att.pub"}
		e[1]["attesterKeys"] = []string{"att.pub"}
	}
	expectOK(t, chain(t, c.manifest(withAtt)))

	// The epoch key alone must not be enough for ordinary entries.
	(&trustcore.Recorder{Attester: c.keys[1], Log: l}).Record(ev)
	expectFail(t, chain(t, c.manifest(withAtt)), "entry 2: not signed by a trusted attester")
}

func TestChainBadManifest(t *testing.T) {
	c := newChain(t, 1)
	c.planned()
	for name, edit := range map[string]func([]map[string]any){
		"epochs out of order": func(e []map[string]any) { e[0]["epoch"], e[1]["epoch"] = 2, 1 },
		"missing key file":    func(e []map[string]any) { e[1]["publicKey"] = "keys/none.pub" },
		"accept on epoch 1":   func(e []map[string]any) { e[0]["acceptUnplanned"] = strings.Repeat("a", 64) },
	} {
		if _, err := verify.Chain(c.manifest(edit)); err == nil {
			t.Errorf("%s: manifest accepted", name)
		}
	}
}

// Task test 9: a log written by v0.1.0 verifies unchanged, and as epoch 1
// of a chain.
func TestV010FixtureCompatibility(t *testing.T) {
	const dir = "../testdata/v0.1.0-log"
	const origin = "github.com/XtReL/devsecops-gatekeeper/gatekeeper-evidence/v1"
	pub, err := keys.LoadPublic(filepath.Join(dir, "log.pub"))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := verify.Log(verify.Options{Dir: filepath.Join(dir, "log"), Origin: origin, LogKey: pub,
		Attesters: []attest.Verifier{keys.NewVerifier(pub)}})
	if err != nil || !rep.OK || rep.Size != 3 || rep.Root != "78CdI2/Ifjv/Drgyfo8hb/Mmomii5r64+vr/51Mk7yQ=" {
		t.Fatalf("verify.Log: %v %+v", err, rep)
	}
	m, err := verify.LoadManifest(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	crep := chain(t, m)
	expectOK(t, crep)
	if len(crep.Epochs) != 1 || crep.Epochs[0].Size != 3 || crep.Epochs[0].Root != rep.Root || crep.Epochs[0].Frozen {
		t.Fatalf("chain: %+v", crep)
	}
}
