// The api package defines the abstract api between sigsum servers.
package api

import (
	"context"

	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/submit-token"
	"sigsum.org/sigsum-go/pkg/types"
)

// Interface for log api.
type Log interface {
	GetTreeHead(context.Context) (types.CosignedTreeHead, error)
	GetInclusionProof(context.Context, requests.InclusionProof) (types.InclusionProof, error)
	GetConsistencyProof(context.Context, requests.ConsistencyProof) (types.ConsistencyProof, error)
	GetLeaves(context.Context, requests.Leaves) ([]types.Leaf, error)

	AddLeaf(context.Context, requests.Leaf, *token.SubmitHeader) (bool, error)
}

// Interface for witness api.
type Witness interface {
	GetTreeSize(context.Context, requests.GetTreeSize) (uint64, error)
	AddTreeHead(context.Context, requests.AddTreeHead) (types.Cosignature, error)
}

// Interface for the secondary node's api.
type Secondary interface {
	GetSecondaryTreeHead(context.Context) (types.SignedTreeHead, error)
}
