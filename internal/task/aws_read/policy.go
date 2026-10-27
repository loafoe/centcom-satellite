package aws_read

import "sort"

// iamActionPrefix maps an aws_read service to its IAM action namespace.
var iamActionPrefix = map[string]string{
	"iam":           "iam",
	"sso-admin":     "sso",
	"identitystore": "identitystore",
}

// IAMActions returns the IAM actions the allowlist needs, sorted - the exact
// content of deploy/iam-policy-aws-read.json and the chart's policy.
func IAMActions() []string {
	var out []string
	for svc, ops := range allowlist {
		for name := range ops {
			out = append(out, iamActionPrefix[svc]+":"+name)
		}
	}
	sort.Strings(out)
	return out
}
