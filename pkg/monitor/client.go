package monitor

import (
	"context"

	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/crypto"
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

// Retrieves at most count leaves, starting at index, and check that
// they are included in the latest retrieved tree head.
func (c *monitoringLogClient) getLeaves(ctx context.Context, treeHead *types.TreeHead, req requests.Leaves) ([]types.Leaf, error) {
	leaves, err := c.client.GetLeaves(ctx, req)
	if err != nil {
		return nil, err
	}
	// TODO: Do batch inclusion verification.
	for i, leaf := range leaves {
		leafHash := leaf.ToHash()
		if treeHead.Size == 1 {
			if leafHash != treeHead.RootHash {
				return nil, newAlert(AlertLogError, "tree size = 1, but leaf hash != root hash")
			}
		} else {
			proof, err := c.client.GetInclusionProof(ctx,
				requests.InclusionProof{Size: treeHead.Size, LeafHash: leafHash})
			if err != nil {
				return nil, newAlert(AlertLogError, "get-inclusion-proof failed: %v", err)
			}
			if got, want := proof.LeafIndex, req.StartIndex+uint64(i); got != want {
				return nil, newAlert(AlertLogError, "unexpected get-inclusion-proof index, got %d, want %d", got, want)
			}
			if err := proof.Verify(&leafHash, treeHead); err != nil {
				return nil, newAlert(AlertLogError, "inclusion proof for leaf %d not valid", proof.LeafIndex)
			}
		}
	}
	return leaves, nil
}
