// Package attest turns events into signed in-toto attestations: an in-toto
// Statement v1 wrapped in a DSSE envelope.
package attest

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/XtReL/trust-core/event"
)

const (
	// StatementType is the in-toto Statement v1 type URI.
	StatementType = "https://in-toto.io/Statement/v1"
	// PayloadType is the DSSE payload type for in-toto statements.
	PayloadType = "application/vnd.in-toto+json"
)

// Statement is an in-toto Statement v1.
type Statement struct {
	Type          string          `json:"_type"`
	Subject       []event.Subject `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// StatementFromEvent validates the event and converts it to a Statement.
func StatementFromEvent(ev event.Event) (Statement, error) {
	if err := ev.Validate(); err != nil {
		return Statement{}, err
	}
	return Statement{
		Type:          StatementType,
		Subject:       ev.Subjects,
		PredicateType: ev.PredicateType,
		Predicate:     ev.Predicate,
	}, nil
}

// ParseStatement decodes and structurally validates a Statement payload.
func ParseStatement(payload []byte) (Statement, error) {
	var st Statement
	if err := json.Unmarshal(payload, &st); err != nil {
		return Statement{}, fmt.Errorf("attest: statement is not valid JSON: %w", err)
	}
	if st.Type != StatementType {
		return Statement{}, fmt.Errorf("attest: unexpected statement _type %q", st.Type)
	}
	if len(st.Subject) == 0 || st.PredicateType == "" {
		return Statement{}, errors.New("attest: statement is missing subject or predicateType")
	}
	return st, nil
}
