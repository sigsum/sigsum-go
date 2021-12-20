package types

import "strings"

type Endpoint string

const (
	EndpointAddLeaf             = Endpoint("add-leaf")
	EndpointAddCosignature      = Endpoint("add-cosignature")
	EndpointGetTreeHeadLatest   = Endpoint("get-tree-head-latest")
	EndpointGetTreeHeadToSign   = Endpoint("get-tree-head-to-sign")
	EndpointGetTreeHeadCosigned = Endpoint("get-tree-head-cosigned")
	EndpointGetInclusionProof   = Endpoint("get-inclusion-proof")
	EndpointGetConsistencyProof = Endpoint("get-consistency-proof")
	EndpointGetLeaves           = Endpoint("get-leaves")
)

// Path joins a number of components to form a full endpoint path.  For example,
// EndpointAddLeaf.Path("example.com", "sigsum/v0") -> example.com/sigsum/v0/add-leaf.
func (e Endpoint) Path(components ...string) string {
	return strings.Join(append(components, string(e)), "/")
}
