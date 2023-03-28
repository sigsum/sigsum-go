package submit

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/mocks"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/proof"
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

	logKeyHash := crypto.HashBytes(logPub[:])

	policy, err := policy.NewKofNPolicy([]crypto.PublicKey{logPub}, nil, 0)
	if err != nil {
		t.Fatalf("creating policy failed: %v", err)
	}
	tree := merkle.NewTree()

	oneTest := func(i int) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		client := mocks.NewMockLogClient(ctrl)

		msg, sth, inclusionProof, req, leaf, leafHash := prepareResponse(t, submitSigner, logSigner, &tree, i)
		client.EXPECT().AddLeaf(gomock.Any(), req, gomock.Any()).Return(false, nil)
		client.EXPECT().AddLeaf(gomock.Any(), req, gomock.Any()).Return(true, nil)
		client.EXPECT().GetTreeHead(gomock.Any()).Return(
			types.CosignedTreeHead{SignedTreeHead: sth}, nil)
		if len(inclusionProof.Path) > 0 {
			client.EXPECT().GetInclusionProof(gomock.Any(), gomock.Any()).Return(inclusionProof, nil)
		}
		pr, err := submitLeafToLog(context.Background(), policy,
			client, &logKeyHash, nil, func(_ context.Context) error { return nil },
			&req, &leafHash)
		if err != nil {
			t.Errorf("submit failed: %v", err)
		} else {
			pr.Leaf = proof.NewShortLeaf(&leaf)
			if err := pr.Verify(&msg, &submitPub, policy); err != nil {
				t.Errorf("returned sigsum proof failed to verify: %v", err)
			}
		}
	}
	for i := 1; i < 10; i++ {
		oneTest(i)
	}
}

func TestSubmitFailure(t *testing.T) {
	logPub, logSigner, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatalf("creating log key failed: %v", err)
	}

	submitPub, submitSigner, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatalf("creating submit key failed: %v", err)
	}

	logKeyHash := crypto.HashBytes(logPub[:])

	policy, err := policy.NewKofNPolicy([]crypto.PublicKey{logPub}, nil, 0)
	if err != nil {
		t.Fatalf("creating policy failed: %v", err)
	}
	tree := merkle.NewTree()

	oneTest := func(i int) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		client := mocks.NewMockLogClient(ctrl)

		msg, sth, inclusionProof, req, leaf, leafHash := prepareResponse(t, submitSigner, logSigner, &tree, i)
		var addError, getTHError, getInclusionError error
		switch i {
		case 1:
			leaf.Checksum[0] ^= 1
		case 2:
			sth.Signature[0] ^= 1
		case 3:
			inclusionProof.Path[0][0] ^= 1
		case 4:
			leafHash[0] ^= 1
		case 5:
			addError = errors.New("mock error")
		case 6:
			getTHError = errors.New("mock error")
		case 7:
			getInclusionError = errors.New("mock error")
		}
		client.EXPECT().AddLeaf(gomock.Any(), req, gomock.Any()).Return(true, addError)
		client.EXPECT().GetTreeHead(gomock.Any()).Return(
			types.CosignedTreeHead{SignedTreeHead: sth}, getTHError).AnyTimes()
		client.EXPECT().GetInclusionProof(gomock.Any(), gomock.Any()).Return(inclusionProof, getInclusionError).AnyTimes()
		pr, err := submitLeafToLog(context.Background(), policy,
			client, &logKeyHash, nil, func(_ context.Context) error { return nil },
			&req, &leafHash)
		if err == nil {
			pr.Leaf = proof.NewShortLeaf(&leaf)
			err := pr.Verify(&msg, &submitPub, policy)
			if err == nil {
				t.Errorf("case %d submit and verify succeeded; should have failed", i)
			}
		}
	}
	for i := 1; i <= 7; i++ {
		oneTest(i)
	}
}

func prepareResponse(t *testing.T, submitSigner, logSigner crypto.Signer, tree *merkle.Tree, i int) (crypto.Hash, types.SignedTreeHead, types.InclusionProof, requests.Leaf, types.Leaf, crypto.Hash) {
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
	return msg, sth, inclusionProof, req, leaf, leafHash
}
