package tlog_test

import (
	"bytes"
	"testing"

	"github.com/XtReL/trust-core/keys"
	"github.com/XtReL/trust-core/tlog"
)

func TestCheckpointRoundTrip(t *testing.T) {
	_, priv, _ := keys.Generate()
	s := keys.NewSigner(priv)
	cp := tlog.Checkpoint{Origin: "example.com/log", Size: 42, Root: tlog.LeafHash([]byte("x"))}
	signed, err := tlog.SignCheckpoint(cp, s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tlog.OpenCheckpoint(signed, "example.com/log", s.Public())
	if err != nil || got != cp {
		t.Fatalf("open: %v %+v", err, got)
	}
	if _, err := tlog.OpenCheckpoint(signed, "example.com/other", s.Public()); err == nil {
		t.Fatal("accepted wrong origin")
	}
	tampered := bytes.Replace(signed, []byte("\n42\n"), []byte("\n43\n"), 1)
	if _, err := tlog.OpenCheckpoint(tampered, "example.com/log", s.Public()); err == nil {
		t.Fatal("accepted tampered size")
	}
	_, other, _ := keys.Generate()
	if _, err := tlog.OpenCheckpoint(signed, "example.com/log", keys.NewSigner(other).Public()); err == nil {
		t.Fatal("accepted wrong key")
	}
}

func TestParseRejects(t *testing.T) {
	for _, bad := range []string{"", "o\n1\n", "o\n01\nAAAA\n", "has space\n1\nAAAA\n", "o\n1\nnot-base64\n"} {
		if _, err := tlog.ParseCheckpoint([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
