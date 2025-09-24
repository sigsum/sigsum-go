package ui

import (
	"fmt"
	"sigsum.org/sigsum-go/pkg/policy"
)

// The trust policy to use can come from different places:
//   - file explicitly specified by the user
//   - policy name explicitly specified by the user
//   - policy name extracted from a pubkey
//
// This function takes three strings corresponding to the above three cases
// and determines a policy based on that.
func SelectPolicy(policyFile string, policyName string, policyNameFromPubKey string) (*policy.Policy, error) {
	if policyFile != "" && policyName != "" {
		err := fmt.Errorf("both policyFile and policyName were specified, this is not allowed")
		return nil, err
	}
	if policyFile != "" {
		return policy.ReadPolicyFile(policyFile)
	}
	if policyName != "" {
		return policy.ByName(policyName)
	}
	if policyNameFromPubKey != "" {
		return policy.ByName(policyNameFromPubKey)
	}
	// The user has not specified any policy
	return nil, nil
}
