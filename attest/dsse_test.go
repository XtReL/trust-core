package attest_test

import (
	"encoding/base64"
	"testing"

	"github.com/XtReL/trust-core/attest"
	"github.com/XtReL/trust-core/keys"
)

// Test vector from the DSSE protocol specification.
func TestPAEVector(t *testing.T) {
	got := string(attest.PAE("http://example.com/HelloWorld", []byte("hello world")))
	want := "DSSEv1 29 http://example.com/HelloWorld 11 hello world"
	if got != want {
		t.Fatalf("PAE = %q, want %q", got, want)
	}
}

func signer(t *testing.T) *keys.Signer {
	t.Helper()
	_, priv, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return keys.NewSigner(priv)
}

func TestSignVerify(t *testing.T) {
	s, other := signer(t), signer(t)
	env, err := attest.SignEnvelope(attest.PayloadType, []byte(`{"a":1}`), s)
	if err != nil {
		t.Fatal(err)
	}
	payload, ids, err := attest.VerifyEnvelope(env, []attest.Verifier{keys.NewVerifier(s.Public())})
	if err != nil || string(payload) != `{"a":1}` || len(ids) != 1 {
		t.Fatalf("verify: %v %q %v", err, payload, ids)
	}
	if _, _, err := attest.VerifyEnvelope(env, []attest.Verifier{keys.NewVerifier(other.Public())}); err == nil {
		t.Fatal("verified with an untrusted key")
	}
	tampered := env
	tampered.Payload = base64.StdEncoding.EncodeToString([]byte(`{"a":2}`))
	if _, _, err := attest.VerifyEnvelope(tampered, []attest.Verifier{keys.NewVerifier(s.Public())}); err == nil {
		t.Fatal("verified a tampered payload")
	}
	retyped := env
	retyped.PayloadType = "text/plain"
	if _, _, err := attest.VerifyEnvelope(retyped, []attest.Verifier{keys.NewVerifier(s.Public())}); err == nil {
		t.Fatal("verified with a changed payloadType")
	}
}
