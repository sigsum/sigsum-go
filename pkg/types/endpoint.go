package types

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

// Path adds endpoint name to a service prefix.  If prefix is empty, nothing is added.
// For example,
// EndpointAddLeaf.Path("example.com/sigsum") -> "example.com/sigsum/add-leaf".
// EndpointAddLeaf.Path("") -> "add-leaf".
func (e Endpoint) Path(prefix string) string {
	if len(prefix) == 0 {
		return string(e)
	}
	return prefix + "/" + string(e)
}
