package types

import "strings"

type Endpoint string

const (
	EndpointAddLeaf             = Endpoint("add-leaf")
	EndpointAddCosignature      = Endpoint("add-cosignature")
	EndpointGetNextTreeHead     = Endpoint("get-next-tree-head")
	EndpointGetTreeHead         = Endpoint("get-tree-head")
	EndpointGetInclusionProof   = Endpoint("get-inclusion-proof/")
	EndpointGetConsistencyProof = Endpoint("get-consistency-proof/")
	EndpointGetLeaves           = Endpoint("get-leaves/")

	EndpointGetTreeHeadUnsigned = Endpoint("get-tree-head-unsigned")
)

// Path joins a number of components to form a full endpoint path.  For example,
// EndpointAddLeaf.Path("example.com", "sigsum") -> example.com/sigsum/add-leaf.
func (e Endpoint) Path(components ...string) string {
	return strings.Join(append(components, string(e)), "/")
}
