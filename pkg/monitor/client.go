package monitor

import (
	"context"
	"fmt"

	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

// A monitoringLogClient can retrieve tree heads and leafs from a log,
// and it verifies consistency and inclusion of anything it returns.
type monitoringLogClient struct {
	logKey crypto.PublicKey // Identifies the log monitored.
	client client.Log
}

func newMonitoringLogClient(logKey *crypto.PublicKey, URL string) *monitoringLogClient {
	return &monitoringLogClient{
		logKey: *logKey,
		client: client.New(client.Config{URL: URL, UserAgent: "sigsum-monitor"}),
	}
}

// Request log's tree head, and check that it is consistent with local
// state. TODO: Figure out cosignatures should be processed; it would
// make some sense to return a CosignedTreeHead but where only
// properly verified cosignatures are kept.
func (c *monitoringLogClient) getTreeHead(ctx context.Context, treeHead *types.TreeHead) (types.SignedTreeHead, error) {
	cth, err := c.client.GetTreeHead(ctx)
	if err != nil {
		return types.SignedTreeHead{}, newAlert(AlertLogError, "get-tree-head failed: %v", err)
	}
	// For now, only check log's signature. TODO: Also check cosignatures.
	if !cth.Verify(&c.logKey) {
		return types.SignedTreeHead{}, newAlert(AlertInvalidLogSignature, "log signature invalid")
	}
	if cth.Size < treeHead.Size {
		return types.SignedTreeHead{}, newAlert(AlertInconsistentTreeHead, "monitored log has shrunk, size %d, previous size %d", cth.Size, treeHead.Size)
	}
	var proof types.ConsistencyProof
	if treeHead.Size > 0 && cth.Size > treeHead.Size {
		var err error
		proof, err = c.client.GetConsistencyProof(ctx, requests.ConsistencyProof{OldSize: treeHead.Size, NewSize: cth.Size})
		if err != nil {
			return types.SignedTreeHead{}, newAlert(AlertLogError, "get-consistency-proof failed: %v", err)
		}
	}
	if err := proof.Verify(treeHead, &cth.TreeHead); err != nil {
		return types.SignedTreeHead{}, newAlert(AlertInconsistentTreeHead, "consistency proof not valid: %v", err)
	}
	return cth.SignedTreeHead, nil
}

func (c *monitoringLogClient) getInclusionProofAtIndex(ctx context.Context,
	index uint64, req requests.InclusionProof) (types.InclusionProof, error) {
	if req.Size == 1 {
		// Trivial proof: index 0, empty path
		return types.InclusionProof{}, nil
	}
	proof, err := c.client.GetInclusionProof(ctx, req)
	if err != nil {
		return types.InclusionProof{}, newAlert(AlertLogError, "get-inclusion-proof failed: %v", err)
	}
	if proof.LeafIndex != index {
		return types.InclusionProof{}, newAlert(AlertLogError, "unexpected get-inclusion-proof index, got %d, want %d", proof.LeafIndex, index)
	}

	return proof, nil
}

// Caches previous leaf hash and inclusion proof. Valid only for
// retrieving the next range starting at LeafIndex + 1, and with the
// same tree head.
type getLeavesState struct {
	leafHash crypto.Hash
	proof    types.InclusionProof
}

// Retrieves at most count leaves, starting at index, and check that
// they are included in the latest retrieved tree head.
func (c *monitoringLogClient) getLeaves(ctx context.Context, state *getLeavesState, treeHead *types.TreeHead, req requests.Leaves) ([]types.Leaf, *getLeavesState, error) {
	leaves, err := c.client.GetLeaves(ctx, req)
	if err != nil {
		return nil, nil, err
	}

	start := req.StartIndex
	end := req.StartIndex + uint64(len(leaves))

	leafHashes := make([]crypto.Hash, 0, len(leaves)+1)
	var proof types.InclusionProof

	if state != nil {
		if state.proof.LeafIndex+1 != req.StartIndex {
			panic(fmt.Sprintf("invalid state, LeafIndex (%d), StartIndex (%d) should be adjacent",
				state.proof.LeafIndex, req.StartIndex))
		}
		start = state.proof.LeafIndex
		proof = state.proof
		leafHashes = append(leafHashes, state.leafHash)
	}
	for _, leaf := range leaves {
		leafHashes = append(leafHashes, leaf.ToHash())
	}
	if state == nil {
		var err error
		proof, err = c.getInclusionProofAtIndex(ctx, start,
			requests.InclusionProof{Size: treeHead.Size, LeafHash: leafHashes[0]})
		if err != nil {
			return nil, nil, err
		}
	}

	if len(leaves) == 1 {
		if err := proof.Verify(&leafHashes[0], treeHead); err != nil {
			return nil, nil, newAlert(AlertLogError, "inclusion proof for leaf %d not valid", proof.LeafIndex)
		}
		return leaves, &getLeavesState{leafHash: leafHashes[0], proof: proof}, nil
	}

	if end == treeHead.Size {
		if err := merkle.VerifyInclusionTail(leafHashes, start, &treeHead.RootHash, proof.Path); err != nil {
			return nil, nil, newAlert(AlertLogError, "inclusion proof not valid for tail range %d:%d: %v",
				start, end, err)
		}
		return leaves, nil, nil
	}

	endProof, err := c.getInclusionProofAtIndex(ctx, end-1,
		requests.InclusionProof{Size: treeHead.Size, LeafHash: leafHashes[len(leafHashes)-1]})
	if err != nil {
		return nil, nil, err
	}
	if err := merkle.VerifyInclusionBatch(leafHashes, start, treeHead.Size, &treeHead.RootHash, proof.Path, endProof.Path); err != nil {
		return nil, nil, newAlert(AlertLogError, "inclusion proof not valid for range %d:%d: %v", start, end, err)
	}

	return leaves, &getLeavesState{leafHash: leafHashes[len(leafHashes)-1], proof: endProof}, nil
}
