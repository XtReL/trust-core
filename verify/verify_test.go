package verify_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	trustcore "github.com/XtReL/trust-core"
	"github.com/XtReL/trust-core/attest"
	"github.com/XtReL/trust-core/event"
	"github.com/XtReL/trust-core/keys"
	"github.com/XtReL/trust-core/tlog/filelog"
	"github.com/XtReL/trust-core/verify"
)

const origin = "trust.example.com/test/gatekeeper"

type fixture struct {
	dir      string
	logKey   *keys.Signer
	attester *keys.Signer
}

func newFixture(t *testing.T, n int) fixture {
	t.Helper()
	_, lp, _ := keys.Generate()
	_, ap, _ := keys.Generate()
	f := fixture{dir: t.TempDir(), logKey: keys.NewSigner(lp), attester: keys.NewSigner(ap)}
	l, err := filelog.Init(f.dir, origin, f.logKey)
	if err != nil {
		t.Fatal(err)
	}
	rec := trustcore.Recorder{Attester: f.attester, Log: l}
	for i := 0; i < n; i++ {
		ev, err := event.NewTestResult(
			[]event.Subject{{Name: "git+https://github.com/example/repo", Digest: map[string]string{"gitCommit": "0123456789abcdef0123456789abcdef0123456" + string(rune('0'+i))}}},
			event.TestResult{Result: event.ResultPassed, Configuration: []event.ResourceDescriptor{{Name: "rules.toml", Digest: map[string]string{"sha256": "ab"}}}},
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rec.Record(ev); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f fixture) opts() verify.Options {
	return verify.Options{Dir: f.dir, Origin: origin, LogKey: f.logKey.Public(),
		Attesters: []attest.Verifier{keys.NewVerifier(f.attester.Public())}}
}

func TestValidLog(t *testing.T) {
	f := newFixture(t, 5)
	rep, err := verify.Log(f.opts())
	if err != nil || !rep.OK || rep.Size != 5 {
		t.Fatalf("expected valid log: %v %+v", err, rep)
	}
}

func TestTamperedEntry(t *testing.T) {
	f := newFixture(t, 3)
	p := filelog.EntryPath(f.dir, 1)
	data, _ := os.ReadFile(p)
	data[len(data)-3] ^= 1
	os.WriteFile(p, data, 0o644)
	if rep, _ := verify.Log(f.opts()); rep.OK {
		t.Fatal("tampered entry not detected")
	}
}

func TestDeletedEntry(t *testing.T) {
	f := newFixture(t, 3)
	os.Remove(filelog.EntryPath(f.dir, 2))
	if rep, _ := verify.Log(f.opts()); rep.OK {
		t.Fatal("deleted entry not detected")
	}
}

func TestUntrustedAttester(t *testing.T) {
	f := newFixture(t, 2)
	_, other, _ := keys.Generate()
	o := f.opts()
	o.Attesters = []attest.Verifier{keys.NewVerifier(keys.NewSigner(other).Public())}
	if rep, _ := verify.Log(o); rep.OK {
		t.Fatal("entries from an untrusted attester accepted")
	}
}

// The operator holds the log key, so it can rebuild a consistent-looking
// log. Only a checkpoint kept by someone else (client, auditor, witness)
// exposes the rewrite. This is why checkpoints must leave the operator.
func TestHistoryRewriteDetectedByPreviousCheckpoint(t *testing.T) {
	f := newFixture(t, 3)
	kept, _ := os.ReadFile(filelog.CheckpointPath(f.dir))

	// Operator rewrites entry 0 and re-signs everything with the same keys.
	rewritten := t.TempDir()
	l, _ := filelog.Init(rewritten, origin, f.logKey)
	rec := trustcore.Recorder{Attester: f.attester, Log: l}
	for i := 0; i < 4; i++ {
		ev, _ := event.NewTestResult(
			[]event.Subject{{Name: "repo", Digest: map[string]string{"gitCommit": "ffffffffffffffffffffffffffffffffffffff0" + string(rune('0'+i))}}},
			event.TestResult{Result: event.ResultPassed, Configuration: []event.ResourceDescriptor{{Name: "rules.toml"}}},
		)
		rec.Record(ev)
	}
	o := f.opts()
	o.Dir = rewritten
	if rep, _ := verify.Log(o); !rep.OK {
		t.Fatal("a re-signed log should look valid on its own")
	}
	o.Previous = kept
	if rep, _ := verify.Log(o); rep.OK {
		t.Fatal("history rewrite not detected with the kept checkpoint")
	}
	// Honest growth passes the same check.
	o = f.opts()
	o.Previous = kept
	lh, _ := filelog.Open(f.dir, origin, f.logKey)
	(&trustcore.Recorder{Attester: f.attester, Log: lh}).Record(mustEvent(t))
	if rep, _ := verify.Log(o); !rep.OK || rep.PreviousSize == nil || *rep.PreviousSize != 3 {
		t.Fatalf("honest growth rejected: %+v", rep)
	}
}

func mustEvent(t *testing.T) event.Event {
	ev, err := event.NewTestResult(
		[]event.Subject{{Name: "repo", Digest: map[string]string{"gitCommit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}},
		event.TestResult{Result: event.ResultFailed, Configuration: []event.ResourceDescriptor{{Name: "rules.toml"}}, FailedTests: []string{"aws-access-token"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestSingleEntryProof(t *testing.T) {
	f := newFixture(t, 7)
	for i := uint64(0); i < 7; i++ {
		p, err := verify.Prove(f.dir, i)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(p)
		var back verify.Proof
		json.Unmarshal(raw, &back)
		entry, _ := os.ReadFile(filelog.EntryPath(f.dir, i))
		if err := verify.Entry(entry, back, origin, f.logKey.Public(), f.opts().Attesters); err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		other, _ := os.ReadFile(filelog.EntryPath(f.dir, (i+1)%7))
		if verify.Entry(other, back, origin, f.logKey.Public(), nil) == nil {
			t.Fatalf("entry %d: proof accepted a different entry", i)
		}
	}
}

func TestOpenRefusesForeignKey(t *testing.T) {
	f := newFixture(t, 1)
	_, other, _ := keys.Generate()
	if _, err := filelog.Open(f.dir, origin, keys.NewSigner(other)); err == nil {
		t.Fatal("opened a log with the wrong operator key")
	}
	if _, err := filelog.Open(filepath.Join(f.dir), origin, f.logKey); err != nil {
		t.Fatal(err)
	}
}
