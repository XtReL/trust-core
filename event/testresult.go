package event

import (
	"encoding/json"
	"errors"
	"fmt"
)

// PredicateTestResult is the in-toto test-result predicate type. Gatekeeper
// uses it to attest one scan run: each scanning rule is a "test".
const PredicateTestResult = "https://in-toto.io/attestation/test-result/v0.1"

// Test-result outcomes defined by the predicate spec.
const (
	ResultPassed = "PASSED"
	ResultWarned = "WARNED"
	ResultFailed = "FAILED"
)

// ResourceDescriptor is the subset of the in-toto ResourceDescriptor used in
// predicates (for example to pin the rule set and scanner version).
type ResourceDescriptor struct {
	Name        string            `json:"name,omitempty"`
	URI         string            `json:"uri,omitempty"`
	Digest      map[string]string `json:"digest,omitempty"`
	MediaType   string            `json:"mediaType,omitempty"`
	Annotations map[string]any    `json:"annotations,omitempty"`
}

// TestResult is the in-toto test-result v0.1 predicate.
type TestResult struct {
	Result        string               `json:"result"`
	Configuration []ResourceDescriptor `json:"configuration"`
	URL           string               `json:"url,omitempty"`
	PassedTests   []string             `json:"passedTests,omitempty"`
	WarnedTests   []string             `json:"warnedTests,omitempty"`
	FailedTests   []string             `json:"failedTests,omitempty"`
}

// NewTestResult builds a validated Event carrying a test-result predicate.
func NewTestResult(subjects []Subject, tr TestResult) (Event, error) {
	switch tr.Result {
	case ResultPassed, ResultWarned, ResultFailed:
	default:
		return Event{}, fmt.Errorf("event: result must be PASSED, WARNED or FAILED, got %q", tr.Result)
	}
	if len(tr.Configuration) == 0 {
		return Event{}, errors.New("event: test-result requires at least one configuration descriptor")
	}
	raw, err := json.Marshal(tr)
	if err != nil {
		return Event{}, err
	}
	ev := Event{Subjects: subjects, PredicateType: PredicateTestResult, Predicate: raw}
	return ev, ev.Validate()
}
