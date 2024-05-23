package submit

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/proof"
	"sigsum.org/sigsum-go/pkg/requests"
	token "sigsum.org/sigsum-go/pkg/submit-token"
	"sigsum.org/sigsum-go/pkg/types"
)

// TODO: Mostly duplicated in pkg/monitor/client_test.go.
// Implements api.Log.
// TODO: Move to some public package, and add an RWMutex for
// syncronization.
type testLog struct {
	leaves []types.Leaf
	tree   merkle.Tree
	signer crypto.Signer
	r      *rand.Rand
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
	if l.r != nil {
		// Randomly return Accepted (202) rather than OK (200) fro new leaves.
		if _, err := l.tree.GetLeafIndex(&h); err != nil && l.r.Intn(2) > 0 {
			return false, nil
		}
	}
	if l.tree.AddLeafHash(&h) {
		l.leaves = append(l.leaves, leaf)
	}
	return true, nil
}

// Test the success path of submitting to a single log.
func TestBatchSuccess(t *testing.T) {
	logPub, logSigner, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatalf("creating log key failed: %v", err)
	}

	submitPub, submitSigner, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatalf("creating submit key failed: %v", err)
	}

	policy, err := policy.NewKofNPolicy([]crypto.PublicKey{logPub}, nil, 0)
	if err != nil {
		t.Fatalf("creating policy failed: %v", err)
	}

	batch := newBatchWithWorkers(
		context.Background(),
		&Config{
			PerLogTimeout: 5 * time.Minute, // Essentially never
			PollDelay:     100 * time.Millisecond,
			Policy:        policy,
		},
		[]*batchWorker{
			&batchWorker{
				url:        "https://log.example.org/",
				logKeyHash: crypto.HashBytes(logPub[:]),
				cli: &testLog{
					signer: logSigner,
					tree:   merkle.NewTree(),
					r:      rand.New(rand.NewSource(1)),
				},
				c: make(chan *itemState),
			},
		})

	message_id := uint32(0)

	for size := 1; size < 5; size++ {
		messages := make([]crypto.Hash, size)
		proofs := make([]*proof.SigsumProof, size)

		for i := 0; i < size; i++ {
			i := i
			message_id++
			binary.BigEndian.PutUint32(messages[i][:4], message_id)
			batch.SubmitMessage(submitSigner, &messages[i], func(pr proof.SigsumProof) {
				proofs[i] = &pr
			})
		}
		err := batch.Wait()
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < size; i++ {
			if proofs[i] == nil {
				t.Errorf("Proof %d of %d missing", i, size)
			} else {
				t.Logf("Got proof with leaf index: %d", proofs[i].Inclusion.LeafIndex)
				if err := proofs[i].Verify(&messages[i], map[crypto.Hash]crypto.PublicKey{
					crypto.HashBytes(submitPub[:]): submitPub}, policy); err != nil {
					t.Errorf("Proof %d of %d failed to verify: %v", i, size, err)
				}
			}
		}
	}
	if err := batch.Close(); err != nil {
		t.Fatal(err)
	}
}
