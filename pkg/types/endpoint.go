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

	// Witness api.
	EndpointAddCheckpoint = Endpoint("add-checkpoint")
)

// Path adds endpoint name to a service prefix.  If prefix is empty, nothing is added.
// If prefix is non-empty, and doesn't end with a slash, a separating slash is added.
// For example,
// EndpointAddLeaf.Path("example.com/sigsum") -> "example.com/sigsum/add-leaf".
// EndpointAddLeaf.Path("example.com/sigsum/") -> "example.com/sigsum/add-leaf".
// EndpointAddLeaf.Path("") -> "add-leaf".
func (e Endpoint) Path(prefix string) string {
	// Add slash, if prefix is non-empty and doesn't already end with a slash.
	if len(prefix) > 0 && prefix[len(prefix)-1] != '/' {
		prefix += "/"
	}
	return prefix + string(e)
}
