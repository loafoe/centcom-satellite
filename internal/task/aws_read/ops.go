package aws_read

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
)

// opFunc decodes params into the SDK input type and performs one API call.
type opFunc func(ctx context.Context, cfg aws.Config, params json.RawMessage) (any, error)

// op binds an SDK client constructor and a client method expression into an
// opFunc, so the allowlist below is a table of real typed SDK calls - there
// is no reflection-based "call any method by name" path to escape it.
func op[C any, O any, In any, Out any](newClient func(aws.Config) C, fn func(C, context.Context, *In, ...func(*O)) (*Out, error)) opFunc {
	return func(ctx context.Context, cfg aws.Config, params json.RawMessage) (any, error) {
		in := new(In)
		if err := decodeParams(params, in); err != nil {
			return nil, err
		}
		return fn(newClient(cfg), ctx, in)
	}
}

func iamClient(cfg aws.Config) *iam.Client           { return iam.NewFromConfig(cfg) }
func ssoAdminClient(cfg aws.Config) *ssoadmin.Client { return ssoadmin.NewFromConfig(cfg) }
func identityStoreClient(cfg aws.Config) *identitystore.Client {
	return identitystore.NewFromConfig(cfg)
}

// allowlist is the complete set of AWS operations aws_read can perform. Every
// entry is a List/Get/Describe call, plus IAM's two report generators
// (GenerateCredentialReport, GenerateServiceLastAccessedDetails), which AWS
// classifies as Read-level: they start a report job and change no access
// configuration. Nothing here returns secret material - IAM never returns an
// access key's secret or a password after creation. Adding an operation is a
// code change and a matching IAM policy change (chart features.awsRead).
var allowlist = map[string]map[string]opFunc{
	"iam": {
		"GetAccountAuthorizationDetails":            op(iamClient, (*iam.Client).GetAccountAuthorizationDetails),
		"GetAccountSummary":                         op(iamClient, (*iam.Client).GetAccountSummary),
		"GetAccountPasswordPolicy":                  op(iamClient, (*iam.Client).GetAccountPasswordPolicy),
		"ListAccountAliases":                        op(iamClient, (*iam.Client).ListAccountAliases),
		"GenerateCredentialReport":                  op(iamClient, (*iam.Client).GenerateCredentialReport),
		"GetCredentialReport":                       op(iamClient, (*iam.Client).GetCredentialReport),
		"ListUsers":                                 op(iamClient, (*iam.Client).ListUsers),
		"GetUser":                                   op(iamClient, (*iam.Client).GetUser),
		"ListUserTags":                              op(iamClient, (*iam.Client).ListUserTags),
		"GetLoginProfile":                           op(iamClient, (*iam.Client).GetLoginProfile),
		"ListGroupsForUser":                         op(iamClient, (*iam.Client).ListGroupsForUser),
		"ListAttachedUserPolicies":                  op(iamClient, (*iam.Client).ListAttachedUserPolicies),
		"ListUserPolicies":                          op(iamClient, (*iam.Client).ListUserPolicies),
		"GetUserPolicy":                             op(iamClient, (*iam.Client).GetUserPolicy),
		"ListMFADevices":                            op(iamClient, (*iam.Client).ListMFADevices),
		"ListVirtualMFADevices":                     op(iamClient, (*iam.Client).ListVirtualMFADevices),
		"ListAccessKeys":                            op(iamClient, (*iam.Client).ListAccessKeys),
		"GetAccessKeyLastUsed":                      op(iamClient, (*iam.Client).GetAccessKeyLastUsed),
		"ListGroups":                                op(iamClient, (*iam.Client).ListGroups),
		"GetGroup":                                  op(iamClient, (*iam.Client).GetGroup),
		"ListAttachedGroupPolicies":                 op(iamClient, (*iam.Client).ListAttachedGroupPolicies),
		"ListGroupPolicies":                         op(iamClient, (*iam.Client).ListGroupPolicies),
		"GetGroupPolicy":                            op(iamClient, (*iam.Client).GetGroupPolicy),
		"ListRoles":                                 op(iamClient, (*iam.Client).ListRoles),
		"GetRole":                                   op(iamClient, (*iam.Client).GetRole),
		"ListRoleTags":                              op(iamClient, (*iam.Client).ListRoleTags),
		"ListAttachedRolePolicies":                  op(iamClient, (*iam.Client).ListAttachedRolePolicies),
		"ListRolePolicies":                          op(iamClient, (*iam.Client).ListRolePolicies),
		"GetRolePolicy":                             op(iamClient, (*iam.Client).GetRolePolicy),
		"ListPolicies":                              op(iamClient, (*iam.Client).ListPolicies),
		"GetPolicy":                                 op(iamClient, (*iam.Client).GetPolicy),
		"GetPolicyVersion":                          op(iamClient, (*iam.Client).GetPolicyVersion),
		"ListEntitiesForPolicy":                     op(iamClient, (*iam.Client).ListEntitiesForPolicy),
		"GenerateServiceLastAccessedDetails":        op(iamClient, (*iam.Client).GenerateServiceLastAccessedDetails),
		"GetServiceLastAccessedDetails":             op(iamClient, (*iam.Client).GetServiceLastAccessedDetails),
		"GetServiceLastAccessedDetailsWithEntities": op(iamClient, (*iam.Client).GetServiceLastAccessedDetailsWithEntities),
		"ListSAMLProviders":                         op(iamClient, (*iam.Client).ListSAMLProviders),
		"ListOpenIDConnectProviders":                op(iamClient, (*iam.Client).ListOpenIDConnectProviders),
	},
	"sso-admin": {
		"ListInstances":                                      op(ssoAdminClient, (*ssoadmin.Client).ListInstances),
		"ListPermissionSets":                                 op(ssoAdminClient, (*ssoadmin.Client).ListPermissionSets),
		"DescribePermissionSet":                              op(ssoAdminClient, (*ssoadmin.Client).DescribePermissionSet),
		"ListPermissionSetsProvisionedToAccount":             op(ssoAdminClient, (*ssoadmin.Client).ListPermissionSetsProvisionedToAccount),
		"ListAccountAssignments":                             op(ssoAdminClient, (*ssoadmin.Client).ListAccountAssignments),
		"ListAccountAssignmentsForPrincipal":                 op(ssoAdminClient, (*ssoadmin.Client).ListAccountAssignmentsForPrincipal),
		"ListAccountsForProvisionedPermissionSet":            op(ssoAdminClient, (*ssoadmin.Client).ListAccountsForProvisionedPermissionSet),
		"ListManagedPoliciesInPermissionSet":                 op(ssoAdminClient, (*ssoadmin.Client).ListManagedPoliciesInPermissionSet),
		"ListCustomerManagedPolicyReferencesInPermissionSet": op(ssoAdminClient, (*ssoadmin.Client).ListCustomerManagedPolicyReferencesInPermissionSet),
		"GetInlinePolicyForPermissionSet":                    op(ssoAdminClient, (*ssoadmin.Client).GetInlinePolicyForPermissionSet),
	},
	"identitystore": {
		"ListUsers":                     op(identityStoreClient, (*identitystore.Client).ListUsers),
		"DescribeUser":                  op(identityStoreClient, (*identitystore.Client).DescribeUser),
		"ListGroups":                    op(identityStoreClient, (*identitystore.Client).ListGroups),
		"DescribeGroup":                 op(identityStoreClient, (*identitystore.Client).DescribeGroup),
		"ListGroupMemberships":          op(identityStoreClient, (*identitystore.Client).ListGroupMemberships),
		"ListGroupMembershipsForMember": op(identityStoreClient, (*identitystore.Client).ListGroupMembershipsForMember),
	},
}
