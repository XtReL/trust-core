package event_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/XtReL/trust-core/event"
)

func TestEpochOrigin(t *testing.T) {
	const base = "github.com/XtReL/devsecops-gatekeeper/gatekeeper-evidence/v1"
	for k := 1; k <= 12; k++ {
		o := event.EpochOrigin(base, k)
		got, err := event.ParseEpoch(base, o)
		if err != nil || got != k {
			t.Fatalf("epoch %d: origin %q parsed as %d, %v", k, o, got, err)
		}
	}
	if o := event.EpochOrigin(base, 2); o != base+"/e2" {
		t.Fatalf("EpochOrigin(base, 2) = %q", o)
	}
	for _, bad := range []string{base + "/e1", base + "/e0", base + "/e02", base + "/e", base + "/e2x", base + "/x/e2", "other/e2", base + "e2"} {
		if k, err := event.ParseEpoch(base, bad); err == nil {
			t.Fatalf("ParseEpoch accepted %q as epoch %d", bad, k)
		}
	}
}

func validGenesis() event.LogGenesis {
	return event.LogGenesis{
		Epoch:                 2,
		PredecessorOrigin:     "example.com/log",
		PredecessorSize:       3,
		PredecessorRoot:       base64.StdEncoding.EncodeToString(make([]byte, 32)),
		PredecessorCheckpoint: "example.com/log\n3\n...\n",
		PredecessorKeyID:      strings.Repeat("a", 64),
		NewKeyID:              strings.Repeat("b", 64),
		Rotation:              event.RotationPlanned,
	}
}

func TestNewLogGenesis(t *testing.T) {
	ev, err := event.NewLogGenesis(validGenesis())
	if err != nil {
		t.Fatal(err)
	}
	if ev.PredicateType != event.PredicateLogGenesis || len(ev.Subjects) != 1 ||
		ev.Subjects[0].Name != "example.com/log" || ev.Subjects[0].Digest["sha256"] != strings.Repeat("00", 32) {
		t.Fatalf("unexpected event: %+v", ev)
	}
	for name, mut := range map[string]func(*event.LogGenesis){
		"epoch 1":         func(g *event.LogGenesis) { g.Epoch = 1 },
		"rotation":        func(g *event.LogGenesis) { g.Rotation = "retired" },
		"uppercase keyid": func(g *event.LogGenesis) { g.NewKeyID = strings.Repeat("B", 64) },
		"short keyid":     func(g *event.LogGenesis) { g.PredecessorKeyID = "abcd" },
		"same key":        func(g *event.LogGenesis) { g.NewKeyID = g.PredecessorKeyID },
		"root not base64": func(g *event.LogGenesis) { g.PredecessorRoot = "!!" },
		"root 31 bytes":   func(g *event.LogGenesis) { g.PredecessorRoot = base64.StdEncoding.EncodeToString(make([]byte, 31)) },
		"no origin":       func(g *event.LogGenesis) { g.PredecessorOrigin = "" },
		"no checkpoint":   func(g *event.LogGenesis) { g.PredecessorCheckpoint = "" },
	} {
		g := validGenesis()
		mut(&g)
		if _, err := event.NewLogGenesis(g); err == nil {
			t.Errorf("%s: invalid genesis accepted", name)
		}
	}
}
