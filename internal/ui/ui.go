package ui

import (
	"fmt"
	"sigsum.org/sigsum-go/pkg/policy"
)

type PolicyParams struct {
	File           string // Typically from -p (--policy) option
	Name           string // Typically from -P (--named-policy) option
	NameFromPubKey string // Policy name found in pubkey file
}

// The trust policy to use can come from different places:
//   - file explicitly specified by the user
//   - policy name explicitly specified by the user
//   - policy name extracted from a pubkey
//
// This function takes a struct with three strings corresponding to
// the above three cases and determines a policy based on that.
func SelectPolicy(params PolicyParams) (*policy.Policy, error) {
	if params.File != "" && params.Name != "" {
		err := fmt.Errorf("both policy file and policy name were specified, this is not allowed")
		return nil, err
	}
	if params.File != "" {
		return policy.ReadPolicyFile(params.File)
	}
	if params.Name != "" {
		return policy.ByName(params.Name)
	}
	if params.NameFromPubKey != "" {
		return policy.ByName(params.NameFromPubKey)
	}
	// The user has not specified any policy
	return nil, nil
}
