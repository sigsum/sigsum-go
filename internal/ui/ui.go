package ui

import (
	"fmt"
	"sigsum.org/sigsum-go/pkg/policy"
)

type PolicySelectionParams struct {
	PolicyFile           string // Typically from -p (--policy) option
	PolicyName           string // Typically from -P (--named-policy) option
	PolicyNameFromPubKey string // Policy name found in pubkey file
}

// The trust policy to use can come from different places:
//   - file explicitly specified by the user
//   - policy name explicitly specified by the user
//   - policy name extracted from a pubkey
//
// This function takes a struct with three strings corresponding to
// the above three cases and determines a policy based on that.
func SelectPolicy(params PolicySelectionParams) (*policy.Policy, error) {
	if params.PolicyFile != "" && params.PolicyName != "" {
		err := fmt.Errorf("both policyFile and policyName were specified, this is not allowed")
		return nil, err
	}
	if params.PolicyFile != "" {
		return policy.ReadPolicyFile(params.PolicyFile)
	}
	if params.PolicyName != "" {
		return policy.ByName(params.PolicyName)
	}
	if params.PolicyNameFromPubKey != "" {
		return policy.ByName(params.PolicyNameFromPubKey)
	}
	// The user has not specified any policy
	return nil, nil
}
