package attest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// Signer signs DSSE pre-authentication encodings.
type Signer interface {
	KeyID() string
	Sign(msg []byte) ([]byte, error)
}

// Verifier checks signatures made by one trusted key.
type Verifier interface {
	KeyID() string
	Verify(msg, sig []byte) bool
}

// Signature is one DSSE signature. KeyID is an unauthenticated hint.
type Signature struct {
	KeyID string `json:"keyid,omitempty"`
	Sig   string `json:"sig"`
}

// Envelope is a DSSE envelope (https://github.com/secure-systems-lab/dsse).
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// PAE is the DSSE v1 pre-authentication encoding:
// "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body.
// Signing PAE (not the raw payload) binds the payload type to the signature.
func PAE(payloadType string, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString("DSSEv1 ")
	b.WriteString(strconv.Itoa(len(payloadType)))
	b.WriteByte(' ')
	b.WriteString(payloadType)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(len(payload)))
	b.WriteByte(' ')
	b.Write(payload)
	return b.Bytes()
}

// SignEnvelope creates an envelope signed by every signer.
func SignEnvelope(payloadType string, payload []byte, signers ...Signer) (Envelope, error) {
	if len(signers) == 0 {
		return Envelope{}, errors.New("attest: at least one signer is required")
	}
	pae := PAE(payloadType, payload)
	env := Envelope{PayloadType: payloadType, Payload: base64.StdEncoding.EncodeToString(payload)}
	for _, s := range signers {
		sig, err := s.Sign(pae)
		if err != nil {
			return Envelope{}, fmt.Errorf("attest: signing with %s: %w", s.KeyID(), err)
		}
		env.Signatures = append(env.Signatures, Signature{KeyID: s.KeyID(), Sig: base64.StdEncoding.EncodeToString(sig)})
	}
	return env, nil
}

// SignStatement serialises a statement and signs it into an envelope.
func SignStatement(st Statement, signers ...Signer) (Envelope, error) {
	payload, err := json.Marshal(st)
	if err != nil {
		return Envelope{}, err
	}
	return SignEnvelope(PayloadType, payload, signers...)
}

func decodeB64(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// VerifyEnvelope returns the payload if at least one signature verifies
// against a trusted key, together with the IDs of the keys that verified.
// A key ID hint that does not match a verifier is skipped (fail closed).
func VerifyEnvelope(env Envelope, trusted []Verifier) ([]byte, []string, error) {
	if len(trusted) == 0 {
		return nil, nil, errors.New("attest: no trusted keys supplied")
	}
	payload, err := decodeB64(env.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("attest: payload is not base64: %w", err)
	}
	pae := PAE(env.PayloadType, payload)
	seen := map[string]bool{}
	var accepted []string
	for _, s := range env.Signatures {
		sig, err := decodeB64(s.Sig)
		if err != nil {
			continue
		}
		for _, v := range trusted {
			if s.KeyID != "" && s.KeyID != v.KeyID() {
				continue
			}
			if !seen[v.KeyID()] && v.Verify(pae, sig) {
				seen[v.KeyID()] = true
				accepted = append(accepted, v.KeyID())
			}
		}
	}
	if len(accepted) == 0 {
		return nil, nil, errors.New("attest: no valid signature from a trusted key")
	}
	return payload, accepted, nil
}
