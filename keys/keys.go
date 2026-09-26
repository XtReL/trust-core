// Package keys manages Ed25519 keys stored as standard PEM files
// (PKCS#8 private, PKIX public), so they are readable by openssl and other
// tooling. Private keys are written with 0600 permissions and never
// overwritten.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// KeyID is the lowercase hex SHA-256 of the raw 32-byte public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// Generate creates a new Ed25519 key pair.
func Generate() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// WritePrivate stores a private key as PKCS#8 PEM. It refuses to overwrite.
func WritePrivate(path string, priv ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("keys: %w (refusing to overwrite an existing key)", err)
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// WritePublic stores a public key as PKIX PEM.
func WritePublic(path string, pub ed25519.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644)
}

func readPEM(path, want string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != want {
		return nil, fmt.Errorf("keys: %s does not contain a %s PEM block", path, want)
	}
	return block.Bytes, nil
}

// LoadPublic reads an Ed25519 public key from a PKIX PEM file.
func LoadPublic(path string) (ed25519.PublicKey, error) {
	der, err := readPEM(path, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("keys: public key is not Ed25519")
	}
	return pub, nil
}

// Signer is an Ed25519 signer usable for DSSE envelopes and log checkpoints.
type Signer struct {
	priv ed25519.PrivateKey
	id   string
}

// NewSigner wraps a private key.
func NewSigner(priv ed25519.PrivateKey) *Signer {
	return &Signer{priv: priv, id: KeyID(priv.Public().(ed25519.PublicKey))}
}

// LoadSigner reads an Ed25519 private key from a PKCS#8 PEM file.
func LoadSigner(path string) (*Signer, error) {
	der, err := readPEM(path, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("keys: private key is not Ed25519")
	}
	return NewSigner(priv), nil
}

// KeyID returns the signer's key ID.
func (s *Signer) KeyID() string { return s.id }

// Public returns the signer's public key.
func (s *Signer) Public() ed25519.PublicKey { return s.priv.Public().(ed25519.PublicKey) }

// Sign signs msg with Ed25519.
func (s *Signer) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.priv, msg), nil }

// Verifier checks signatures from one Ed25519 public key.
type Verifier struct {
	pub ed25519.PublicKey
	id  string
}

// NewVerifier wraps a public key.
func NewVerifier(pub ed25519.PublicKey) *Verifier { return &Verifier{pub: pub, id: KeyID(pub)} }

// KeyID returns the verifier's key ID.
func (v *Verifier) KeyID() string { return v.id }

// Verify reports whether sig is a valid Ed25519 signature of msg.
func (v *Verifier) Verify(msg, sig []byte) bool { return ed25519.Verify(v.pub, msg, sig) }
