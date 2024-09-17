// The api package defines the abstract api between sigsum servers.
package api

import (
	"context"

	"sigsum.org/sigsum-go/pkg/checkpoint"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/submit-token"
	"sigsum.org/sigsum-go/pkg/types"
)

// Interface for Sigsum's log api, corresponding to the end points of
// the HTTP wire protocol. Implementations of this interface are
// expected to support requests for trivial inclusion and consistency
// proofs, even though such requests are not allowed on the wire.
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
	AddTreeHead(context.Context, requests.AddTreeHead) (crypto.Hash, types.Cosignature, error)
	AddCheckpoint(context.Context, requests.AddCheckpoint) ([]checkpoint.CosignatureLine, error)
}

// Interface for the secondary node's api.
type Secondary interface {
	GetSecondaryTreeHead(context.Context) (types.SignedTreeHead, error)
}
