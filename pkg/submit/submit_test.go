package submit

import (
	"context"
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

func TestSubmit(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := mocks.NewMockLogClient(ctrl)

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

	for i := 1; i < 10; i++ {
		msg := crypto.HashBytes([]byte{byte(i)})
		signature, err := types.SignLeafMessage(submitSigner, msg[:])
		if err != nil {
			t.Fatalf("signing message failed: %v", err)
		}

		req := requests.Leaf{
			Message:   msg,
			Signature: signature,
			PublicKey: submitPub,
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

		client.EXPECT().AddLeaf(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil)
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
}
