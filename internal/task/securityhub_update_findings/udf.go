package securityhub_update_findings

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	itypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

const (
	// maxResourceIDs caps resource_ids; maxResolved caps how many findings a
	// vulnerability selection may address in one call.
	maxResourceIDs = 200
	maxResolved    = 2000
	// Inspector accepts at most 10 values per string filter, Security Hub 20.
	inspectorIDsPerCall   = 10
	securityHubIDsPerCall = 20
	// ASFF UserDefinedFields limits.
	maxUDFKey   = 128
	maxUDFValue = 1024
)

// resolveVulnerability returns the Security Hub identifiers of every active
// Inspector finding for vulnID (on resourceIDs, if given). An Inspector
// finding's ARN is its Security Hub finding ID; the product ARN is the
// Inspector integration's in the finding's own region.
func resolveVulnerability(ctx context.Context, insp inspectorAPI, vulnID string, resourceIDs []string) ([]FindingRef, error) {
	eq := func(v string) itypes.StringFilter {
		return itypes.StringFilter{Comparison: itypes.StringComparisonEquals, Value: aws.String(v)}
	}
	var batches [][]string
	for i := 0; i < len(resourceIDs); i += inspectorIDsPerCall {
		batches = append(batches, resourceIDs[i:min(i+inspectorIDsPerCall, len(resourceIDs))])
	}
	if len(batches) == 0 {
		batches = [][]string{nil}
	}
	seen := map[string]bool{}
	var refs []FindingRef
	for _, ids := range batches {
		fc := &itypes.FilterCriteria{
			VulnerabilityId: []itypes.StringFilter{eq(vulnID)},
			FindingStatus:   []itypes.StringFilter{eq("ACTIVE")},
		}
		for _, id := range ids {
			fc.ResourceId = append(fc.ResourceId, eq(id))
		}
		var next *string
		for {
			out, err := insp.ListFindings(ctx, &inspector2.ListFindingsInput{FilterCriteria: fc, MaxResults: aws.Int32(100), NextToken: next})
			if err != nil {
				return nil, err
			}
			for _, f := range out.Findings {
				arn := aws.ToString(f.FindingArn)
				if arn == "" || seen[arn] {
					continue
				}
				seen[arn] = true
				refs = append(refs, FindingRef{ID: arn, ProductArn: inspectorProductArn(arn)})
				if len(refs) > maxResolved {
					return nil, fmt.Errorf("%s matches more than %d findings; narrow it with resource_ids", vulnID, maxResolved)
				}
			}
			if aws.ToString(out.NextToken) == "" {
				break
			}
			next = out.NextToken
		}
	}
	return refs, nil
}

// inspectorProductArn derives the Security Hub product ARN for an Inspector
// finding ARN (arn:aws:inspector2:<region>:<account>:finding/<id>).
func inspectorProductArn(findingArn string) string {
	parts := strings.Split(findingArn, ":")
	partition, region := "aws", ""
	if len(parts) > 3 {
		partition, region = parts[1], parts[3]
	}
	return fmt.Sprintf("arn:%s:securityhub:%s::product/aws/inspector", partition, region)
}

// updateUserDefinedFields applies the requested key changes on top of each
// finding's current map and writes findings grouped by resulting map.
// Findings Security Hub doesn't return are reported unprocessed rather than
// written blind, which would wipe whatever keys they carry.
//
// Every selected finding is written, even when the map read back already
// looks right: Security Hub applies updates asynchronously (seen live: a
// read seconds after a write still returned the old map), so a skip based
// on that read could leave a just-written key in place.
func updateUserDefinedFields(ctx context.Context, client api, base securityhub.BatchUpdateFindingsInput, p *Payload, refs []FindingRef, result *UpdateResult) error {
	current, err := readUserDefinedFields(ctx, client, refs)
	if err != nil {
		return err
	}
	groups := map[string][]FindingRef{}
	maps := map[string]map[string]string{}
	for _, ref := range refs {
		cur, ok := current[ref.ID]
		if !ok {
			result.Unprocessed = append(result.Unprocessed, UnprocessedFinding{ID: ref.ID, ProductArn: ref.ProductArn, ErrorCode: "NotFound", ErrorMessage: "finding not found in Security Hub"})
			continue
		}
		next := map[string]string{}
		for k, v := range cur {
			next[k] = v
		}
		for k, v := range p.SetUserDefinedFields {
			next[k] = v
		}
		for _, k := range p.RemoveUserDefinedFields {
			delete(next, k)
		}
		key := canonical(next)
		groups[key] = append(groups[key], ref)
		maps[key] = next
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		in := base
		in.UserDefinedFields = maps[k]
		if err := batchUpdate(ctx, client, in, groups[k], result); err != nil {
			return err
		}
	}
	return nil
}

// readUserDefinedFields returns each found finding's current map (empty, not
// nil, for a finding without one), keyed by finding ID.
func readUserDefinedFields(ctx context.Context, client api, refs []FindingRef) (map[string]map[string]string, error) {
	out := map[string]map[string]string{}
	for start := 0; start < len(refs); start += securityHubIDsPerCall {
		filters := &types.AwsSecurityFindingFilters{}
		for _, r := range refs[start:min(start+securityHubIDsPerCall, len(refs))] {
			filters.Id = append(filters.Id, types.StringFilter{Comparison: types.StringFilterComparisonEquals, Value: aws.String(r.ID)})
		}
		var next *string
		for {
			res, err := client.GetFindings(ctx, &securityhub.GetFindingsInput{Filters: filters, MaxResults: aws.Int32(100), NextToken: next})
			if err != nil {
				return nil, err
			}
			for _, f := range res.Findings {
				m := map[string]string{}
				for k, v := range f.UserDefinedFields {
					m[k] = v
				}
				out[aws.ToString(f.Id)] = m
			}
			if aws.ToString(res.NextToken) == "" {
				break
			}
			next = res.NextToken
		}
	}
	return out, nil
}

// canonical is a stable grouping key for a map (encoding/json sorts keys).
func canonical(m map[string]string) string {
	b, _ := json.Marshal(m)
	return string(b)
}
