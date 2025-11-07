package types

import (
	"testing"
)

func TestPath(t *testing.T) {
	for i, tt := range []struct {
		prefix   string
		endpoint Endpoint
		expected string
	}{
		//  Empty prefix
		{"", EndpointAddLeaf, "add-leaf"},
		// Trailing slash preserved
		{"", EndpointGetLeaves, "get-leaves/"},
		// Typical prefixes, with and without trailing slash
		{"http://example.org", EndpointGetTreeHead,
			"http://example.org/get-tree-head"},
		{"http://example.org/", EndpointGetInclusionProof,
			"http://example.org/get-inclusion-proof/"},
		{"https://example.org/base", EndpointGetConsistencyProof,
			"https://example.org/base/get-consistency-proof/"},
		{"http://example.org/base/", EndpointGetSecondaryTreeHead,
			"http://example.org/base/get-secondary-tree-head"},
		// Extra slash, for those that really want
		{"http://example.org/base//", EndpointAddCheckpoint,
			"http://example.org/base//add-checkpoint"},
	} {
		if got, want := tt.endpoint.Path(tt.prefix), tt.expected; got != want {
			t.Errorf("Failed endpoint.Path test %d: prefix %q, endpoint %q, got %q, want %q", i, tt.prefix, tt.endpoint, got, want)
		}
	}
}
