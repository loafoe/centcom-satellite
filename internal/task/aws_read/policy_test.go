package aws_read

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// The shipped IAM policy must grant exactly the allowlisted operations:
// nothing missing (calls would fail AccessDenied) and nothing extra.
func TestDeployPolicyMatchesAllowlist(t *testing.T) {
	raw, err := os.ReadFile("../../../deploy/iam-policy-aws-read.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Statement []struct {
			Action []string `json:"Action"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, st := range doc.Statement {
		got = append(got, st.Action...)
	}
	slices.Sort(got)
	if want := IAMActions(); !slices.Equal(got, want) {
		t.Fatalf("deploy/iam-policy-aws-read.json actions\n got: %v\nwant: %v", got, want)
	}
}
