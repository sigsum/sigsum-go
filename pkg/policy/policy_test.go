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
		t.Errorf("verifying treehead for log 0 with log hash 1 succeeded")
	}
}

func TestWitnessPolicy(t *testing.T) {
	th := types.TreeHead{Size: 3}
	logPub, logSigner, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	logHash := crypto.HashBytes(logPub[:])
	origin := types.SigsumCheckpointOrigin(&logPub)

	sth, err := th.Sign(logSigner)
	if err != nil {
		t.Fatal(err)
	}

	var witnessKeys []crypto.PublicKey
	var witnessHashes []crypto.Hash
	var cosignatures []types.Cosignature

	for i := 0; i < 5; i++ {
		pub, s, err := crypto.NewKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		cosignature, err := th.Cosign(s, origin, 0)
		if err != nil {
			t.Fatal(err)
		}

		cosignatures = append(cosignatures, cosignature)
		witnessKeys = append(witnessKeys, pub)
		witnessHashes = append(witnessHashes, crypto.HashBytes(pub[:]))
	}
	// Four known witnesses, at least 3 cosignatures required.
	p, err := NewKofNPolicy([]crypto.PublicKey{logPub},
		witnessKeys[:4], 3)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []struct {
		desc        string
		w           []int // Indices of witnesses to include
		invalidate  int   // Signature to invalidate (-1 if none)
		expectValid bool
	}{
		{"no cosignature", nil, -1, false},
		{"only one cosignature", []int{0}, -1, false},
		{"only two cosignatures", []int{0, 1, 4}, -1, false},
		{"three cosignature", []int{0, 1, 2}, -1, true},
		{"other three cosignature", []int{1, 2, 3}, -1, true},
		{"all cosignatures", []int{0, 1, 2, 3, 4}, 4, true},
		{"all cosignatures, one invalid", []int{0, 1, 2, 3, 4}, 2, true},
		{"three cosignatures, but one invalid", []int{0, 2, 3, 4}, 2, false},
	} {
		present := make(map[crypto.Hash]types.Cosignature)
		for _, i := range s.w {
			cs := cosignatures[i]
			if i == s.invalidate {
				cs.Signature[3] ^= 1
			}
			present[witnessHashes[i]] = cs
		}
		err := p.VerifyCosignedTreeHead(&logHash,
			&types.CosignedTreeHead{SignedTreeHead: sth, Cosignatures: present})
		if s.expectValid && err != nil {
			t.Errorf("%s: Failed on valid cth: %v", s.desc, err)
		}
		if !s.expectValid && err == nil {
			t.Errorf("%s: Expected error, but got none", s.desc)
		}
	}
}
