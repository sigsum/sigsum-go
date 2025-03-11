package monitor

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"testing"

	"github.com/golang/mock/gomock"

	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/mocks"
	"sigsum.org/sigsum-go/pkg/requests"
	token "sigsum.org/sigsum-go/pkg/submit-token"
	"sigsum.org/sigsum-go/pkg/types"
)

// Implements api.Log.
// TODO: Move to some public package, and add an RWMutex for
// synchronization.
type testLog struct {
	leaves []types.Leaf
	tree   merkle.Tree
	signer crypto.Signer
}

func (l *testLog) GetTreeHead(_ context.Context) (types.CosignedTreeHead, error) {
	th := types.TreeHead{
		Size:     uint64(l.tree.Size()),
		RootHash: l.tree.GetRootHash(),
	}
	sth, err := th.Sign(l.signer)
	return types.CosignedTreeHead{SignedTreeHead: sth}, err
}

func (l *testLog) GetInclusionProof(_ context.Context, req requests.InclusionProof) (types.InclusionProof, error) {
	index, err := l.tree.GetLeafIndex(&req.LeafHash)
	if err != nil || index >= req.Size {
		return types.InclusionProof{}, api.ErrNotFound
	}
	path, err := l.tree.ProveInclusion(index, req.Size)
	return types.InclusionProof{
		LeafIndex: index,
		Path:      path,
	}, err
}

func (l *testLog) GetConsistencyProof(_ context.Context, req requests.ConsistencyProof) (types.ConsistencyProof, error) {
	path, err := l.tree.ProveConsistency(req.OldSize, req.NewSize)
	return types.ConsistencyProof{Path: path}, err
}

func (l *testLog) GetLeaves(_ context.Context, req requests.Leaves) ([]types.Leaf, error) {
	size := l.tree.Size()
	if req.StartIndex >= size || req.EndIndex > size || req.StartIndex >= req.EndIndex {
		return nil, fmt.Errorf("out of range request: start %d, end %d, size %d\n",
			req.StartIndex, req.EndIndex, size)
	}
	return l.leaves[req.StartIndex:req.EndIndex], nil
}

func (l *testLog) AddLeaf(_ context.Context, req requests.Leaf, _ *token.SubmitHeader) (bool, error) {
	leaf, err := req.Verify()
	if err != nil {
		return false, api.ErrForbidden
	}

	h := leaf.ToHash()
	if l.tree.AddLeafHash(&h) {
		l.leaves = append(l.leaves, leaf)
	}
	return true, nil
}

func makeLeafRequest(t *testing.T, signer crypto.Signer, msg *crypto.Hash) requests.Leaf {
	signature, err := types.SignLeafMessage(signer, msg[:])
	if err != nil {
		t.Fatalf("Leaf signing failed: %v\n", err)
	}
	return requests.Leaf{
		Message:   *msg,
		Signature: signature,
		PublicKey: signer.Public(),
	}
}

// Test for successful case.
func TestGetTreeHead(t *testing.T) {
	logSigner := crypto.NewEd25519Signer(&crypto.PrivateKey{2})
	leafSigner := crypto.NewEd25519Signer(&crypto.PrivateKey{3})
	log := testLog{signer: logSigner, tree: merkle.NewTree()}

	monitorClient := monitoringLogClient{
		logKey: logSigner.Public(),
		client: &log,
	}
	r := rand.New(rand.NewSource(10))

	prevTree := types.NewEmptyTreeHead()

	for i := 0; i < 100; i++ {
		// Ensures that batch is of zero size, so that first
		// GetTreeHead returns an empty tree.
		c := uint64(r.Intn(i + 1))
		newSize := log.tree.Size() + c
		addLeaves(t, &log, leafSigner, uint64(i), c)

		sth, err := monitorClient.getTreeHead(context.Background(), &prevTree)
		if err != nil {
			t.Fatalf("GetTreeHead failed: %v", err)
		}
		if got, want := sth.Size, newSize; got != want {
			t.Fatalf("Unexpected log size: got %d, want %d", got, want)
		}
		prevTree = sth.TreeHead
	}
}

// Test for invalid answers from log.
func TestGetTreeHeadErrors(t *testing.T) {
	logSigner := crypto.NewEd25519Signer(&crypto.PrivateKey{2})
	leafSigner := crypto.NewEd25519Signer(&crypto.PrivateKey{3})
	log := testLog{signer: logSigner, tree: merkle.NewTree()}

	addLeaves(t, &log, leafSigner, 0, 20)
	oldTh, err := log.GetTreeHead(context.Background())
	if err != nil {
		t.Fatalf("GetTreeHead failed: %v", err)
	}
	addLeaves(t, &log, leafSigner, 1, 20)
	oneTest := func(description string, mungeTreeHead func(*types.CosignedTreeHead), mungeConsistency func(*types.ConsistencyProof)) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockLog := mocks.NewMockLog(ctrl)

		mockLog.EXPECT().GetTreeHead(gomock.Any()).DoAndReturn(
			func(ctx context.Context) (types.CosignedTreeHead, error) {
				cth, err := log.GetTreeHead(ctx)
				if err == nil && mungeTreeHead != nil {
					mungeTreeHead(&cth)
				}
				return cth, err
			})
		mockLog.EXPECT().GetConsistencyProof(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
			func(ctx context.Context, req requests.ConsistencyProof) (types.ConsistencyProof, error) {
				proof, err := log.GetConsistencyProof(ctx, req)
				if err == nil && mungeConsistency != nil {
					mungeConsistency(&proof)
				}
				return proof, err
			})

		monitorClient := monitoringLogClient{
			logKey: logSigner.Public(),
			client: mockLog,
		}

		_, err := monitorClient.getTreeHead(context.Background(), &oldTh.TreeHead)
		if err == nil {
			if description != "" {
				t.Errorf("%s: Unexpectedly succeeded", description)
			}
			return
		}
		if description == "" {
			t.Fatalf("Unexpected getTreeHead failure: %v", err)
		}
		t.Logf("%s: (expected) failure: %v", description, err)
	}
	oneTest("", nil, nil) // No failure; checks test wireup.
	oneTest("bad signature", func(cth *types.CosignedTreeHead) {
		cth.Signature[2] ^= 1
	}, nil)
	oneTest("bad signature (hash)", func(cth *types.CosignedTreeHead) {
		cth.RootHash[5] ^= 1
	}, nil)
	oldTh.Size++
	oneTest("bad consistency", nil, nil)
}

func addLeaves(t *testing.T, log *testLog, signer crypto.Signer, id, count uint64) {
	oldSize := log.tree.Size()
	for j := uint64(0); j < count; j++ {
		var msg crypto.Hash
		binary.BigEndian.PutUint64(msg[:], id)
		binary.BigEndian.PutUint64(msg[8:], j)
		_, err := log.AddLeaf(context.Background(), makeLeafRequest(t, signer, &msg), nil)
		if err != nil {
			t.Fatalf("AddLeaf failed: %v", err)
		}
	}
	if got, want := log.tree.Size(), oldSize+count; got != want {
		t.Fatalf("Unexpected merkle tree size: got %d, want %d", got, want)
	}
}
