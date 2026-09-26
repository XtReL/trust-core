package keys

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestParseSignerRoundTrip(t *testing.T) {
	pub, priv, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	signer, err := ParseSigner(pemBytes)
	if err != nil {
		t.Fatalf("ParseSigner: %v", err)
	}
	if !bytes.Equal(signer.Public(), pub) {
		t.Fatalf("parsed signer's public key does not match generated key")
	}

	msg := []byte("trust-core")
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !NewVerifier(pub).Verify(msg, sig) {
		t.Fatalf("signature from parsed signer did not verify")
	}
}

func TestParsePublicRoundTrip(t *testing.T) {
	pub, _, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	parsed, err := ParsePublic(pemBytes)
	if err != nil {
		t.Fatalf("ParsePublic: %v", err)
	}
	if !bytes.Equal(parsed, pub) {
		t.Fatalf("parsed public key does not match generated key")
	}
}

func TestLoadSignerAndLoadPublic(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	privPath := dir + "/signer.key"
	pubPath := dir + "/signer.pub"
	if err := WritePrivate(privPath, priv); err != nil {
		t.Fatalf("WritePrivate: %v", err)
	}
	if err := WritePublic(pubPath, pub); err != nil {
		t.Fatalf("WritePublic: %v", err)
	}

	signer, err := LoadSigner(privPath)
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	if !bytes.Equal(signer.Public(), pub) {
		t.Fatalf("loaded signer's public key does not match generated key")
	}

	loadedPub, err := LoadPublic(pubPath)
	if err != nil {
		t.Fatalf("LoadPublic: %v", err)
	}
	if !bytes.Equal(loadedPub, pub) {
		t.Fatalf("loaded public key does not match generated key")
	}
}

func TestParseSignerWrongPEMType(t *testing.T) {
	pub, _, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	if _, err := ParseSigner(pemBytes); err == nil {
		t.Fatalf("ParseSigner accepted a PUBLIC KEY PEM block")
	}
}

func TestParsePublicWrongPEMType(t *testing.T) {
	_, priv, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	if _, err := ParsePublic(pemBytes); err == nil {
		t.Fatalf("ParsePublic accepted a PRIVATE KEY PEM block")
	}
}

func TestParseSignerGarbage(t *testing.T) {
	if _, err := ParseSigner([]byte("not a pem block")); err == nil {
		t.Fatalf("ParseSigner accepted garbage input")
	}
}

func TestParsePublicGarbage(t *testing.T) {
	if _, err := ParsePublic([]byte("not a pem block")); err == nil {
		t.Fatalf("ParsePublic accepted garbage input")
	}
}
