package policy

import (
	"testing"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

func TestLogPolicy(t *testing.T) {
	th := types.TreeHead{Size: 3}
	var cths []types.CosignedTreeHead
	var logKeys []crypto.PublicKey
	var logHashes []crypto.Hash
	for i := 0; i < 3; i++ {
		pub, s, err := crypto.NewKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		sth, err := th.Sign(s)
		if err != nil {
			t.Fatal(err)
		}

		cths = append(cths, types.CosignedTreeHead{SignedTreeHead: sth})
		logKeys = append(logKeys, pub)
		logHashes = append(logHashes, crypto.HashBytes(pub[:]))
	}
	p, err := NewKofNPolicy(logKeys[:2], nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	if err := p.VerifyCosignedTreeHead(&logHashes[0], &cths[0]); err != nil {
		t.Errorf("verifying treehead for log 0 failed: %v", err)
	}
	if err := p.VerifyCosignedTreeHead(&logHashes[1], &cths[1]); err != nil {
		t.Errorf("verifying treehead for log 1 failed: %v", err)
	}
	if err := p.VerifyCosignedTreeHead(&logHashes[2], &cths[2]); err == nil {
		t.Errorf("verifying treehead for log 2 succeeded, but it's not allowed by policy")
	}
	if err := p.VerifyCosignedTreeHead(&logHashes[1], &cths[0]); err == nil {
		t.Errorf("verifying treehead for log 0 with log hash 1 succeeeded")
	}
}
