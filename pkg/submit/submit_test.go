package submit

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/mocks"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

func TestSubmitSuccess(t *testing.T) {
	logPub, logSigner, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatalf("creating log key failed: %v", err)
	}
	submitPub, submitSigner, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatalf("creating submit key failed: %v", err)
	}
	p, err := policy.NewKofNPolicy([]crypto.PublicKey{logPub}, nil, 0)
	if err != nil {
		t.Fatalf("creating policy failed: %v", err)
	}
	tree := merkle.NewTree()
	timeout := 1 * time.Minute

	oneTest := func(t *testing.T, i int) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		client := mocks.NewMockLog(ctrl)
		logs := []logClient{logClient{
			client: client,
			entity: policy.Entity{
				PublicKey: logPub,
				URL:       "http://example.org",
			},
		}}

		msg, sth, inclusionProof, req := prepareResponse(t, submitSigner, logSigner, &tree, i)
		client.EXPECT().AddLeaf(gomock.Any(), req, gomock.Any()).Return(false, nil)

		submissions, err := submitLeaves(context.Background(), timeout, logs, []requests.Leaf{req})
		if err != nil {
			t.Errorf("submit failed: %v", err)
			return
		}
		if got, want := len(submissions), 1; got != want {
			t.Errorf("unexpected number of submissions: got %d, want %d", got, want)
			return
		}

		client.EXPECT().AddLeaf(gomock.Any(), req, gomock.Any()).Return(true, nil)
		client.EXPECT().GetTreeHead(gomock.Any()).Return(types.CosignedTreeHead{SignedTreeHead: sth}, nil)
		client.EXPECT().GetInclusionProof(gomock.Any(), gomock.Any()).Return(inclusionProof, nil)

		proofs, err := collectProofs(context.Background(), timeout, nop, p, submissions)
		if err != nil {
			t.Errorf("collect failed: %v", err)
			return
		}
		if got, want := len(proofs), 1; got != want {
			t.Errorf("unexpected number of proofs: got %d, want %d", got, want)
			return
		}

		pr := proofs[0]
		if err := pr.Verify(&msg, map[crypto.Hash]crypto.PublicKey{
			crypto.HashBytes(submitPub[:]): submitPub}, p); err != nil {
			t.Errorf("returned sigsum proof failed to verify: %v", err)
		}
	}

	for i := 1; i < 10; i++ {
		t.Run(fmt.Sprintf("leaf %d", i), func(t *testing.T) { oneTest(t, i) })
	}
}

func TestSubmitWithFailure(t *testing.T) {
	logPub, logSigner, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatalf("creating log key failed: %v", err)
	}
	_, submitSigner, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatalf("creating submit key failed: %v", err)
	}
	p, err := policy.NewKofNPolicy([]crypto.PublicKey{logPub}, nil, 0)
	if err != nil {
		t.Fatalf("creating policy failed: %v", err)
	}
	tree := merkle.NewTree()
	timeout := 1 * time.Minute

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	client := mocks.NewMockLog(ctrl)
	clientAlwaysFail := mocks.NewMockLog(ctrl)
	logs := []logClient{
		logClient{
			client: clientAlwaysFail,
			entity: policy.Entity{
				URL: "http://always-fail.example.org",
			},
		},
		logClient{
			client: client,
			entity: policy.Entity{
				PublicKey: logPub,
				URL:       "http://example.org",
			},
		},
	}

	// Get a few entries added to the tree
	for i := 1; i < 10; i++ {
		prepareResponse(t, submitSigner, logSigner, &tree, i)
	}

	// Both logs fail
	_, sth, inclusionProof, req := prepareResponse(t, submitSigner, logSigner, &tree, 10)
	clientAlwaysFail.EXPECT().AddLeaf(gomock.Any(), req, gomock.Any()).Return(false, errors.New("mock error"))
	client.EXPECT().AddLeaf(gomock.Any(), req, gomock.Any()).Return(false, errors.New("mock error"))

	submissions, err := submitLeaves(context.Background(), timeout, logs, []requests.Leaf{req})
	if err == nil {
		t.Errorf("submit succeeded but shouldn't have")
		return
	}

	// One log succeeds after a whole bunch of retrying
	clientAlwaysFail.EXPECT().AddLeaf(gomock.Any(), req, gomock.Any()).Return(false, errors.New("mock error"))
	client.EXPECT().AddLeaf(gomock.Any(), req, gomock.Any()).Return(false, nil)

	submissions, err = submitLeaves(context.Background(), timeout, logs, []requests.Leaf{req})
	if err != nil {
		t.Errorf("submit failed: %v", err)
		return
	}

	client.EXPECT().AddLeaf(gomock.Any(), req, gomock.Any()).Return(true, errors.New("mock error"))

	client.EXPECT().AddLeaf(gomock.Any(), req, gomock.Any()).Return(false, nil) // not persisted yet

	client.EXPECT().AddLeaf(gomock.Any(), req, gomock.Any()).Return(true, nil)
	client.EXPECT().GetTreeHead(gomock.Any()).Return(types.CosignedTreeHead{}, errors.New("mock error"))

	client.EXPECT().AddLeaf(gomock.Any(), req, gomock.Any()).Return(true, nil)
	client.EXPECT().GetTreeHead(gomock.Any()).Return(types.CosignedTreeHead{}, nil) // bad tree head

	client.EXPECT().AddLeaf(gomock.Any(), req, gomock.Any()).Return(true, nil)
	client.EXPECT().GetTreeHead(gomock.Any()).Return(types.CosignedTreeHead{SignedTreeHead: sth}, nil)
	client.EXPECT().GetInclusionProof(gomock.Any(), gomock.Any()).Return(inclusionProof, errors.New("mock error"))

	client.EXPECT().AddLeaf(gomock.Any(), req, gomock.Any()).Return(true, nil)
	client.EXPECT().GetTreeHead(gomock.Any()).Return(types.CosignedTreeHead{SignedTreeHead: sth}, nil)
	client.EXPECT().GetInclusionProof(gomock.Any(), gomock.Any()).Return(inclusionProof, nil)

	if _, err := collectProofs(context.Background(), timeout, nop, p, submissions); err != nil {
		t.Errorf("collect failed but shouldn't have: %v", err)
		return
	}

	inclusionProof.LeafIndex += 1 // make proof invalid
	client.EXPECT().AddLeaf(gomock.Any(), req, gomock.Any()).Return(true, nil)
	client.EXPECT().GetTreeHead(gomock.Any()).Return(types.CosignedTreeHead{SignedTreeHead: sth}, nil)
	client.EXPECT().GetInclusionProof(gomock.Any(), gomock.Any()).Return(inclusionProof, nil)

	if _, err := collectProofs(context.Background(), timeout, nop, p, submissions); err == nil {
		t.Errorf("collect succeeded but shouldn't have")
		return
	}
}

func prepareResponse(t *testing.T, submitSigner, logSigner crypto.Signer, tree *merkle.Tree, i int) (crypto.Hash, types.SignedTreeHead, types.InclusionProof, requests.Leaf) {
	msg := crypto.HashBytes([]byte{byte(i)})
	signature, err := types.SignLeafMessage(submitSigner, msg[:])
	if err != nil {
		t.Fatalf("signing message failed: %v", err)
	}

	req := requests.Leaf{
		Message:   msg,
		Signature: signature,
		PublicKey: submitSigner.Public(),
	}
	leaf, err := req.Verify()
	if err != nil {
		t.Fatalf("leaf verify failed: %v", err)
	}
	leafHash := leaf.ToHash()
	if !tree.AddLeafHash(&leafHash) {
		t.Fatalf("unexpected leaf duplicate, leaf %d", i)
	}

	th := types.TreeHead{
		RootHash: tree.GetRootHash(),
		Size:     tree.Size(),
	}
	sth, err := th.Sign(logSigner)
	if err != nil {
		t.Fatalf("signing tree head failed: %v", err)
	}

	path, err := tree.ProveInclusion(tree.Size()-1, tree.Size())
	if err != nil {
		t.Fatalf("failed to prove inclusion: %v", err)
	}
	inclusionProof := types.InclusionProof{
		LeafIndex: tree.Size() - 1,
		Path:      path,
	}
	return msg, sth, inclusionProof, req
}

func nop(_ context.Context) error {
	return nil
}
