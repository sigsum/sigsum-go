package submit

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/golang/mock/gomock"

	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/mocks"
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

// Test the success path of submitting to a single log.
func TestBatchSuccess(t *testing.T) {
	submitPub, submitSigner, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatalf("creating submit key failed: %v", err)
	}

	log, logPub, logKeyHash := newTestLog(t)

	policy, err := policy.NewKofNPolicy([]crypto.PublicKey{logPub}, nil, 0)
	if err != nil {
		t.Fatalf("creating policy failed: %v", err)
	}

	r := rand.New(rand.NewSource(1))

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	cli := mocks.NewMockLog(ctrl)

	cli.EXPECT().AddLeaf(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(ctx context.Context, req requests.Leaf, header *token.SubmitHeader) (bool, error) {
			// Randomly return persisted == false for new leaves.
			leaf, err := req.Verify()
			if err != nil {
				return false, api.ErrForbidden
			}

			h := leaf.ToHash()
			if _, err := log.tree.GetLeafIndex(&h); err != nil && r.Intn(2) > 0 {
				return false, nil
			}
			return log.AddLeaf(ctx, req, header)
		})
	cli.EXPECT().GetTreeHead(gomock.Any()).AnyTimes().DoAndReturn(log.GetTreeHead)
	cli.EXPECT().GetInclusionProof(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(log.GetInclusionProof)

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
				logKeyHash: logKeyHash,
				cli:        cli,
				c:          make(chan *itemState),
			},
		})

	message_id := uint32(0)

	for size := 1; size <= 10; size++ {
		messages := make([]crypto.Hash, size)
		proofs := make([]*proof.SigsumProof, size)

		for i := 0; i < size; i++ {
			i := i
			time.Sleep(30 * time.Millisecond)
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
			} else if err := proofs[i].Verify(&messages[i], map[crypto.Hash]crypto.PublicKey{
				crypto.HashBytes(submitPub[:]): submitPub}, policy); err != nil {
				t.Errorf("Proof %d of %d failed to verify: %v", i, size, err)
			}
		}
	}
	if err := batch.Close(); err != nil {
		t.Fatal(err)
	}
}

// Test batch failover.
func TestBatchFailover(t *testing.T) {
	submitPub, submitSigner, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatalf("creating submit key failed: %v", err)
	}

	logA, logAPub, logAKeyHash := newTestLog(t)
	logB, logBPub, logBKeyHash := newTestLog(t)

	policy, err := policy.NewKofNPolicy([]crypto.PublicKey{logAPub, logBPub}, nil, 0)
	if err != nil {
		t.Fatalf("creating policy failed: %v", err)
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	cliB := mocks.NewMockLog(ctrl)

	cliB.EXPECT().AddLeaf(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(ctx context.Context, req requests.Leaf, header *token.SubmitHeader) (bool, error) {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			// Don't persist more than 5 leaves.
			leaf, err := req.Verify()
			if err != nil {
				return false, api.ErrForbidden
			}

			h := leaf.ToHash()
			if _, err := logB.tree.GetLeafIndex(&h); err != nil && logB.tree.Size() >= 5 {
				return false, nil
			}
			return logB.AddLeaf(ctx, req, header)
		})
	cliB.EXPECT().GetTreeHead(gomock.Any()).AnyTimes().DoAndReturn(logB.GetTreeHead)
	cliB.EXPECT().GetInclusionProof(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(logB.GetInclusionProof)

	batch := newBatchWithWorkers(
		context.Background(),
		&Config{
			PerLogTimeout: 1 * time.Second,
			PollDelay:     100 * time.Millisecond,
			Policy:        policy,
		},
		[]*batchWorker{
			&batchWorker{
				url:        "https://logA.example.org/",
				logKeyHash: logAKeyHash,
				cli:        logA,
				c:          make(chan *itemState),
			},
			&batchWorker{
				url:        "https://logB.example.org/",
				logKeyHash: crypto.HashBytes(logBPub[:]),
				cli:        cliB,
				c:          make(chan *itemState),
			},
		})

	message_id := uint32(0)
	doBatch := func(size int) []*proof.SigsumProof {
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
			} else if err := proofs[i].Verify(&messages[i], map[crypto.Hash]crypto.PublicKey{
				crypto.HashBytes(submitPub[:]): submitPub}, policy); err != nil {
				t.Errorf("Proof %d of %d failed to verify: %v", i, size, err)
			}
		}
		return proofs
	}

	leafsByLog := func(proofs []*proof.SigsumProof) map[crypto.Hash][]uint64 {
		m := make(map[crypto.Hash][]uint64)
		for _, pr := range proofs {
			if pr != nil {
				m[pr.LogKeyHash] = append(m[pr.LogKeyHash], pr.Inclusion.LeafIndex)
			}
		}
		return m
	}

	success := leafsByLog(doBatch(7))
	if got, want := success[logAKeyHash], []uint64{0, 1, 2, 3}; !sliceEqual(got, want) {
		t.Errorf("Unexpected logA leafs, got: %v, want: %v", got, want)
	}
	if got, want := success[logBKeyHash], []uint64{0, 1, 2}; !sliceEqual(got, want) {
		t.Errorf("Unexpected logB leafs, got: %v, want: %v", got, want)
	}

	failOver := leafsByLog(doBatch(6))
	// TODO: Unclear why we get proof for leaf 7 before the proof for leaf 6.
	if got, want := failOver[logAKeyHash], []uint64{4, 5, 7, 6}; !sliceEqual(got, want) {
		t.Errorf("Unexpected logA leafs, got: %v, want: %v", got, want)
	}
	if got, want := failOver[logBKeyHash], []uint64{3, 4}; !sliceEqual(got, want) {
		t.Errorf("Unexpected logB leafs, got: %v, want: %v", got, want)
	}

	singleLog := leafsByLog(doBatch(3))
	if got, want := singleLog[logAKeyHash], []uint64{8, 9, 10}; !sliceEqual(got, want) {
		t.Errorf("Unexpected logA leafs, got: %v, want: %v", got, want)
	}
	if got, want := singleLog[logBKeyHash], []uint64{}; !sliceEqual(got, want) {
		t.Errorf("Unexpected logB leafs, got: %v, want: %v", got, want)
	}

	if err := batch.Close(); err != nil {
		t.Fatal(err)
	}
}

// Use a larger number of logs, all failing in different ways.
func TestBatchErrors(t *testing.T) {
	submitPub, submitSigner, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatalf("creating submit key failed: %v", err)
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Log i should accept i+1 leaves (including producing valid proofs).
	newMock := func(i int, log *testLog) api.Log {
		cli := mocks.NewMockLog(ctrl)
		if i == 0 {
			cli.EXPECT().AddLeaf(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
				func(ctx context.Context, req requests.Leaf, header *token.SubmitHeader) (bool, error) {
					if log.tree.Size() > uint64(i) {
						return false, errors.New("mocked add-leaf error")
					}
					return log.AddLeaf(ctx, req, header)
				})
		} else {
			cli.EXPECT().AddLeaf(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(log.AddLeaf)
		}
		if i == 1 {
			cli.EXPECT().GetTreeHead(gomock.Any()).AnyTimes().DoAndReturn(
				func(ctx context.Context) (types.CosignedTreeHead, error) {
					if log.tree.Size() > uint64(i)+1 {
						return types.CosignedTreeHead{}, errors.New("mocked get-tree-head error")
					}
					return log.GetTreeHead(ctx)
				})
		} else if i == 2 {
			cli.EXPECT().GetTreeHead(gomock.Any()).AnyTimes().DoAndReturn(
				func(ctx context.Context) (types.CosignedTreeHead, error) {
					th, err := log.GetTreeHead(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if log.tree.Size() > uint64(i)+1 {
						th.Signature[0] ^= 1
					}
					return th, nil
				})
		} else {
			cli.EXPECT().GetTreeHead(gomock.Any()).AnyTimes().DoAndReturn(log.GetTreeHead)
		}
		if i == 3 {
			cli.EXPECT().GetInclusionProof(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
				func(ctx context.Context, req requests.InclusionProof) (types.InclusionProof, error) {
					inclusion, err := log.GetInclusionProof(ctx, req)
					if err == nil && inclusion.LeafIndex > uint64(i) {
						return types.InclusionProof{}, errors.New("mocked get-inclusion-proof error")
					}
					return inclusion, err
				})
		} else if i == 4 {
			cli.EXPECT().GetInclusionProof(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
				func(ctx context.Context, req requests.InclusionProof) (types.InclusionProof, error) {
					inclusion, err := log.GetInclusionProof(ctx, req)
					if err == nil && inclusion.LeafIndex > uint64(i) {
						inclusion.Path[0][0] ^= 1
					}
					return inclusion, err
				})
		} else {
			cli.EXPECT().GetInclusionProof(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(log.GetInclusionProof)
		}
		return cli
	}

	var logs []*testLog
	var pubKeys []crypto.PublicKey
	var workers []*batchWorker

	for i := 0; i < 5; i++ {
		log, pub, keyHash := newTestLog(t)
		logs = append(logs, log)
		pubKeys = append(pubKeys, pub)
		workers = append(workers, &batchWorker{
			url:        fmt.Sprintf("https://log%d.example.org/", i),
			logKeyHash: keyHash,
			cli:        newMock(i, log),
			c:          make(chan *itemState),
		})
	}

	policy, err := policy.NewKofNPolicy(pubKeys, nil, 0)
	if err != nil {
		t.Fatalf("creating policy failed: %v", err)
	}

	batch := newBatchWithWorkers(
		context.Background(),
		&Config{
			PerLogTimeout: 1 * time.Second,
			PollDelay:     100 * time.Millisecond,
			Policy:        policy,
		},
		workers)

	const size = 16
	messages := make([]crypto.Hash, size)
	proofs := make([]*proof.SigsumProof, size)
	message_id := uint32(0)

	for i := 0; i < size; i++ {
		i := i
		message_id++

		// Do one message at a time, for deterministic
		// behavior (otherwise, a failure for GetTreeHead at a
		// particular size n may affect any preceding leaves,
		// depending on how order of calls.
		if err := batch.Wait(); err != nil {
			t.Fatalf("Unexpected wait failure after %d messages %err", i, err)
		}
		binary.BigEndian.PutUint32(messages[i][:4], message_id)
		t.Logf("Submitting message %d", message_id)

		batch.SubmitMessage(submitSigner, &messages[i], func(pr proof.SigsumProof) {
			proofs[i] = &pr
		})
	}
	if err := batch.Close(); err == nil {
		t.Error("Unexpected success from batch.Close()")
	} else {
		t.Logf("Expected error: %v", err)
	}
	for i := 0; i < size-1; i++ {
		if proofs[i] == nil {
			t.Errorf("Proof %d missing", i)
		} else if err := proofs[i].Verify(&messages[i], &submitPub, policy); err != nil {
			t.Errorf("Proof %d of %d failed to verify: %v", i, size, err)
		}
	}
	if proofs[size-1] != nil {
		t.Errorf("Unexpected proof for final message")
	}
}

func sliceEqual[T comparable](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	for i, x := range a {
		if x != b[i] {
			return false
		}
	}
	return true
}

// Convenience functino to create a testLog and needed keys.
func newTestLog(t *testing.T) (*testLog, crypto.PublicKey, crypto.Hash) {
	pub, signer, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatalf("creating log key failed: %v", err)
	}
	return &testLog{signer: signer, tree: merkle.NewTree()},
		pub, crypto.HashBytes(pub[:])
}
