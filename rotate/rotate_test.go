package rotate_test

import (
	"os"
	"strings"
	"testing"

	trustcore "github.com/XtReL/trust-core"
	"github.com/XtReL/trust-core/event"
	"github.com/XtReL/trust-core/keys"
	"github.com/XtReL/trust-core/rotate"
	"github.com/XtReL/trust-core/tlog/filelog"
)

const base = "trust.example.com/test/evidence"

func newKey(t *testing.T) *keys.Signer {
	t.Helper()
	_, priv, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return keys.NewSigner(priv)
}

func record(t *testing.T, dir, origin string, s *keys.Signer, n int, tag string) {
	t.Helper()
	l, err := filelog.Open(dir, origin, s)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		ev, err := event.NewTestResult(
			[]event.Subject{{Name: "repo", Digest: map[string]string{"gitCommit": strings.Repeat(tag, 39) + string(rune('0'+i))}}},
			event.TestResult{Result: event.ResultPassed, Configuration: []event.ResourceDescriptor{{Name: "rules"}}},
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := (&trustcore.Recorder{Attester: s, Log: l}).Record(ev); err != nil {
			t.Fatal(err)
		}
	}
}

func newLog(t *testing.T, origin string, s *keys.Signer, n int, tag string) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := filelog.Init(dir, origin, s); err != nil {
		t.Fatal(err)
	}
	record(t, dir, origin, s, n, tag)
	return dir
}

func TestPlannedResult(t *testing.T) {
	k1, k2, k3 := newKey(t), newKey(t), newKey(t)
	e1 := newLog(t, base, k1, 3, "a")
	e2 := t.TempDir() + "/e2"
	res, err := rotate.Planned(e1, base, k1, e2, k2, "scheduled")
	if err != nil {
		t.Fatal(err)
	}
	if res.Epoch != 2 || res.Origin != base+"/e2" || res.NewKeyID != k2.KeyID() || res.FrozenSize != 3 || res.AfterFreeze != 0 ||
		!strings.HasPrefix(res.VerifierKey, base+"/e2+") {
		t.Fatalf("unexpected result: %+v", res)
	}
	if _, err := os.Stat(e2 + "/entries/.gitkeep"); err != nil {
		t.Fatal(err)
	}
	// Epoch numbers continue from the origin suffix.
	res, err = rotate.Planned(e2, base+"/e2", k2, t.TempDir()+"/e3", k3, "")
	if err != nil || res.Epoch != 3 || res.Origin != base+"/e3" || res.FrozenSize != 1 {
		t.Fatalf("second rotation: %+v %v", res, err)
	}
}

func TestPlannedRefuses(t *testing.T) {
	k1, k2 := newKey(t), newKey(t)
	e1 := newLog(t, base, k1, 2, "a")
	if _, err := rotate.Planned(e1, base, k2, t.TempDir()+"/x", newKey(t), ""); err == nil {
		t.Fatal("planned rotation with a key that does not sign the old epoch")
	}
	if _, err := rotate.Planned(e1, base, k1, t.TempDir()+"/x", k1, ""); err == nil {
		t.Fatal("rotation to the same key")
	}
	if _, err := rotate.Planned(e1, base, k1, e1, k2, ""); err == nil {
		t.Fatal("rotation into the old directory")
	}
	os.WriteFile(filelog.EntryPath(e1, 2), []byte("{}"), 0o644)
	if _, err := rotate.Planned(e1, base, k1, t.TempDir()+"/x", k2, ""); err == nil {
		t.Fatal("planned rotation with an uncommitted entry file")
	}
}

// Task test 4: the trusted checkpoint does not match the prefix of the old
// epoch, i.e. history was rewritten before the freeze point.
func TestUnplannedRewrittenBeforeFreeze(t *testing.T) {
	k1, k2 := newKey(t), newKey(t)
	e1 := newLog(t, base, k1, 3, "a")
	kept, _ := os.ReadFile(filelog.CheckpointPath(e1))

	// Whoever holds the stolen key rebuilds the log with other entries.
	forged := newLog(t, base, k1, 5, "f")
	_, err := rotate.Unplanned(forged, base, k1.Public(), kept, t.TempDir()+"/e2", k2, "")
	if err == nil || !strings.Contains(err.Error(), "rewritten") {
		t.Fatalf("expected a history rewrite error, got %v", err)
	}
	// A trusted checkpoint from another log or key is refused as well.
	other, _ := os.ReadFile(filelog.CheckpointPath(newLog(t, base, newKey(t), 1, "b")))
	if _, err := rotate.Unplanned(e1, base, k1.Public(), other, t.TempDir()+"/e2", k2, ""); err == nil {
		t.Fatal("trusted checkpoint signed by another key accepted")
	}
	if _, err := rotate.Unplanned(e1, base, k1.Public(), nil, t.TempDir()+"/e2", k2, ""); err == nil {
		t.Fatal("unplanned rotation without a trusted checkpoint")
	}
	// The honest log extends the kept checkpoint; later entries are ignored.
	record(t, e1, base, k1, 2, "c")
	res, err := rotate.Unplanned(e1, base, k1.Public(), kept, t.TempDir()+"/e2", k2, "device lost")
	if err != nil || res.FrozenSize != 3 || res.AfterFreeze != 2 {
		t.Fatalf("unplanned: %+v %v", res, err)
	}
}
