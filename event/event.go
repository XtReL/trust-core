// Package event defines the vertical-agnostic unit that verticals hand to
// Trust Core. A vertical (Gatekeeper, agent action logs, MRV, ...) only builds
// an Event; it never touches signing or the log directly. This is the
// boundary that lets a new vertical plug in without changing the core.
package event

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Subject identifies what an event is about, for example a git commit.
// It serialises as an in-toto ResourceDescriptor (name + digest).
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Event is what a vertical records: one or more subjects, a predicate type
// URI and the predicate itself.
type Event struct {
	Subjects      []Subject       `json:"subjects"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// Validate checks the structural rules Trust Core relies on. It does not
// interpret the predicate: that is the vertical's responsibility.
func (e Event) Validate() error {
	if len(e.Subjects) == 0 {
		return errors.New("event: at least one subject is required")
	}
	for i, s := range e.Subjects {
		if len(s.Digest) == 0 {
			return fmt.Errorf("event: subject %d (%q) has no digest", i, s.Name)
		}
		for alg, v := range s.Digest {
			if alg == "" || v == "" {
				return fmt.Errorf("event: subject %d has an empty digest algorithm or value", i)
			}
			if _, err := hex.DecodeString(v); err != nil || strings.ToLower(v) != v {
				return fmt.Errorf("event: subject %d digest %s must be lowercase hex", i, alg)
			}
		}
	}
	if e.PredicateType == "" {
		return errors.New("event: predicateType is required")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(e.Predicate, &obj); err != nil {
		return fmt.Errorf("event: predicate must be a JSON object: %w", err)
	}
	return nil
}
