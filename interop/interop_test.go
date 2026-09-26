package interop

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/XtReL/trust-core/keys"
	tc "github.com/XtReL/trust-core/tlog"
	"golang.org/x/mod/sumdb/note"
	xt "golang.org/x/mod/sumdb/tlog"
)

func TestOurNoteOpensWithReference(t *testing.T) {
	_, priv, _ := keys.Generate()
	s := keys.NewSigner(priv)
	origin := "trust.example.com/xtrel/gatekeeper"
	signed, err := tc.SignCheckpoint(tc.Checkpoint{Origin: origin, Size: 7, Root: tc.LeafHash([]byte("r"))}, s)
	if err != nil {
		t.Fatal(err)
	}
	v, err := note.NewVerifier(tc.VerifierKey(origin, s.Public()))
	if err != nil {
		t.Fatal("reference rejected our vkey:", err)
	}
	n, err := note.Open(signed, note.VerifierList(v))
	if err != nil {
		t.Fatal("reference rejected our signed checkpoint:", err)
	}
	t.Logf("reference verified note, %d sig(s)", len(n.Sigs))
}

func TestReferenceNoteOpensWithOurs(t *testing.T) {
	skey, vkey, err := note.GenerateKey(rand.Reader, "witness.example.com")
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := note.NewSigner(skey)
	msg, err := note.Sign(&note.Note{Text: "trust.example.com/log\n3\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"}, signer)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(vkey, "+")
	raw, _ := base64.StdEncoding.DecodeString(parts[2])
	pub := ed25519.PublicKey(raw[1:])
	if tc.VerifierKey("witness.example.com", pub) != vkey {
		t.Fatal("our vkey encoding differs from reference")
	}
	if _, err := tc.OpenNote(msg, "witness.example.com", pub); err != nil {
		t.Fatal("we rejected a reference-signed note:", err)
	}
}

type mem []xt.Hash

func (m *mem) ReadHashes(idx []int64) ([]xt.Hash, error) {
	out := make([]xt.Hash, len(idx))
	for i, x := range idx {
		out[i] = (*m)[x]
	}
	return out, nil
}

func TestMerkleMatchesReference(t *testing.T) {
	var store mem
	var ours []tc.Hash
	for n := int64(0); n < 130; n++ {
		data := []byte(fmt.Sprintf("entry-%d", n))
		hs, err := xt.StoredHashes(n, data, &store)
		if err != nil {
			t.Fatal(err)
		}
		store = append(store, hs...)
		ours = append(ours, tc.LeafHash(data))
		size := n + 1
		ref, err := xt.TreeHash(size, &store)
		if err != nil {
			t.Fatal(err)
		}
		if tc.Hash(ref) != tc.RootFromLeaves(ours) {
			t.Fatalf("root mismatch at size %d", size)
		}
		for i := int64(0); i < size; i++ {
			rp, err := xt.ProveRecord(size, i, &store)
			if err != nil {
				t.Fatal(err)
			}
			op, _ := tc.InclusionProof(ours, uint64(i))
			if len(rp) != len(op) {
				t.Fatalf("proof length mismatch size=%d i=%d", size, i)
			}
			conv := make(xt.RecordProof, len(op))
			for j := range op {
				if tc.Hash(rp[j]) != op[j] {
					t.Fatalf("proof element mismatch size=%d i=%d j=%d", size, i, j)
				}
				conv[j] = xt.Hash(op[j])
			}
			if err := xt.CheckRecord(conv, size, ref, i, xt.Hash(ours[i])); err != nil {
				t.Fatalf("reference rejected our proof size=%d i=%d", size, i)
			}
		}
	}
}
