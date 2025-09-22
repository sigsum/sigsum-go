package ui

import (
	"fmt"
	"sigsum.org/sigsum-go/pkg/policy"
)

// The trust policy to use can come from different places:
//   - file explicitly specified by the user
//   - policy name explicitly specified by the user
//   - (in future, not implemented yet) policy name extracted from a pubkey
//
// This function takes strings corresponding to the above cases
// and determines a policy based on that.
// (The plan is to later add a third argument "policyNameFromPubKey")
func SelectPolicy(policyFile string, policyName string) (*policy.Policy, error) {
	if policyFile != "" && policyName != "" {
		err := fmt.Errorf("both policyFile and policyName were specified, this is not allowed")
		return nil, err
	}
	if policyFile != "" {
		policy, err := policy.ReadPolicyFile(policyFile)
		if err != nil {
			err := fmt.Errorf("Invalid policy file: %v", err)
			return nil, err
		}
		return policy, err
	}
	if policyName != "" {
		policy, err := policy.ByName(policyName)
		if err != nil {
			err := fmt.Errorf("policy.ByName failed: %v", err)
			return nil, err
		}
		return policy, err
	}
	// The user has not specified any policy
	return nil, nil
}
