package securityhub_common

import (
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

func TestNormalizeFinding_MapsCoreFields(t *testing.T) {
	sdk := types.AwsSecurityFinding{
		Id:          aws.String("finding-1"),
		ProductArn:  aws.String("arn:aws:securityhub:us-east-1::product/aws/guardduty"),
		ProductName: aws.String("GuardDuty"),
		Title:       aws.String("Some threat"),
		Description: aws.String("A description"),
		Types:       []string{"TTPs/Command and Control"},
		Severity: &types.Severity{
			Label:      types.SeverityLabelHigh,
			Normalized: aws.Int32(70),
		},
		Workflow:     &types.Workflow{Status: types.WorkflowStatusNew},
		RecordState:  types.RecordStateActive,
		AwsAccountId: aws.String("123456789012"),
		Region:       aws.String("us-east-1"),
		CreatedAt:    aws.String("2026-07-01T00:00:00Z"),
		UpdatedAt:    aws.String("2026-07-02T00:00:00Z"),
		Resources: []types.Resource{
			{Id: aws.String("arn:aws:ec2:us-east-1:123456789012:instance/i-1"), Type: aws.String("AwsEc2Instance")},
		},
	}

	got := NormalizeFinding(sdk)

	if got.ID != "finding-1" {
		t.Errorf("ID = %q, want finding-1", got.ID)
	}
	if got.ProductArn != "arn:aws:securityhub:us-east-1::product/aws/guardduty" {
		t.Errorf("ProductArn = %q", got.ProductArn)
	}
	if got.ProductName != "GuardDuty" {
		t.Errorf("ProductName = %q", got.ProductName)
	}
	if got.SeverityLabel != "HIGH" {
		t.Errorf("SeverityLabel = %q, want HIGH", got.SeverityLabel)
	}
	if got.SeverityNormalized != 70 {
		t.Errorf("SeverityNormalized = %d, want 70", got.SeverityNormalized)
	}
	if got.WorkflowStatus != "NEW" {
		t.Errorf("WorkflowStatus = %q, want NEW", got.WorkflowStatus)
	}
	if got.RecordState != "ACTIVE" {
		t.Errorf("RecordState = %q, want ACTIVE", got.RecordState)
	}
	if got.ResourceType != "AwsEc2Instance" {
		t.Errorf("ResourceType = %q, want AwsEc2Instance", got.ResourceType)
	}
	if got.ResourceID != "arn:aws:ec2:us-east-1:123456789012:instance/i-1" {
		t.Errorf("ResourceID = %q", got.ResourceID)
	}
	if got.AWSAccountID != "123456789012" {
		t.Errorf("AWSAccountID = %q", got.AWSAccountID)
	}
	if len(got.Types) != 1 || got.Types[0] != "TTPs/Command and Control" {
		t.Errorf("Types = %v", got.Types)
	}
	if got.Detail == nil {
		t.Fatal("expected Detail to be populated")
	}
	var roundTrip types.AwsSecurityFinding
	// Detail is a marshaled types.AwsSecurityFinding-shaped JSON; just confirm it decodes to valid JSON.
	if err := json.Unmarshal(got.Detail, &roundTrip); err != nil {
		t.Errorf("Detail did not round-trip as JSON: %v", err)
	}
}

func TestNormalizeFinding_NoResourcesLeavesResourceFieldsEmpty(t *testing.T) {
	sdk := types.AwsSecurityFinding{
		Id:         aws.String("finding-2"),
		ProductArn: aws.String("arn:x"),
		Severity:   &types.Severity{Label: types.SeverityLabelLow},
	}
	got := NormalizeFinding(sdk)
	if got.ResourceType != "" || got.ResourceID != "" {
		t.Errorf("expected empty resource fields, got type=%q id=%q", got.ResourceType, got.ResourceID)
	}
}
