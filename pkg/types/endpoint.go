package types

type Endpoint string

const (
	// Sigsum log api.
	EndpointAddLeaf             = Endpoint("add-leaf")
	EndpointGetTreeHead         = Endpoint("get-tree-head")
	EndpointGetInclusionProof   = Endpoint("get-inclusion-proof/")
	EndpointGetConsistencyProof = Endpoint("get-consistency-proof/")
	EndpointGetLeaves           = Endpoint("get-leaves/")

	// For primary/secondary replication.
	EndpointGetSecondaryTreeHead = Endpoint("get-secondary-tree-head")

	// Old Sigsum witness api.
	EndpointAddTreeHead = Endpoint("add-tree-head")
	EndpointGetTreeSize = Endpoint("get-tree-size/")
	// Witness api.
	EndpointAddCheckpoint = Endpoint("add-checkpoint")
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
