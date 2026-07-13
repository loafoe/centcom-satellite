package guardduty_common

import (
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
)

func TestNormalizeFinding(t *testing.T) {
	f := gdtypes.Finding{
		Id:          aws.String("finding-1"),
		Arn:         aws.String("arn:aws:guardduty:eu-west-1:1:detector/d/finding/finding-1"),
		Type:        aws.String("Recon:EC2/PortProbeUnprotectedPort"),
		Title:       aws.String("Unprotected port probed"),
		Description: aws.String("An EC2 instance has an unprotected port."),
		Severity:    aws.Float64(8.0),
		Confidence:  aws.Float64(5.0),
		AccountId:   aws.String("123456789012"),
		Region:      aws.String("eu-west-1"),
		CreatedAt:   aws.String("2026-07-01T00:00:00.000Z"),
		UpdatedAt:   aws.String("2026-07-02T00:00:00.000Z"),
		Resource:    &gdtypes.Resource{ResourceType: aws.String("Instance")},
		Service:     &gdtypes.Service{Count: aws.Int32(3)},
	}

	out := NormalizeFinding(f)

	if out.ID != "finding-1" || out.Type != "Recon:EC2/PortProbeUnprotectedPort" {
		t.Fatalf("unexpected header: %+v", out)
	}
	if out.Severity != 8.0 || out.SeverityLabel != "High" {
		t.Errorf("severity = %v (%q), want 8 High", out.Severity, out.SeverityLabel)
	}
	if out.ResourceType != "Instance" {
		t.Errorf("resource_type = %q, want Instance", out.ResourceType)
	}
	if out.Count != 3 {
		t.Errorf("count = %d, want 3", out.Count)
	}
	if len(out.Detail) == 0 {
		t.Fatal("expected Detail to carry the full finding")
	}
	// Detail must be valid JSON containing the finding ID.
	var raw map[string]any
	if err := json.Unmarshal(out.Detail, &raw); err != nil {
		t.Fatalf("Detail not valid JSON: %v", err)
	}
	if raw["Id"] != "finding-1" {
		t.Errorf("Detail Id = %v, want finding-1", raw["Id"])
	}
}

func TestNormalizeFinding_NilNested(t *testing.T) {
	// Missing Resource/Service must not panic.
	out := NormalizeFinding(gdtypes.Finding{
		Id:       aws.String("f2"),
		Type:     aws.String("t"),
		Severity: aws.Float64(2.0),
	})
	if out.ResourceType != "" || out.Count != 0 {
		t.Errorf("expected empty resource/count, got %+v", out)
	}
	if out.SeverityLabel != "Low" {
		t.Errorf("severity label = %q, want Low", out.SeverityLabel)
	}
}
