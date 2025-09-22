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

type testData struct {
	sth           types.SignedTreeHead
	logPub        crypto.PublicKey
	logHash       crypto.Hash
	witnessKeys   []crypto.PublicKey
	witnessHashes []crypto.Hash
	cosignatures  []types.Cosignature
}

func newTestData(t *testing.T, count int) testData {
	th := types.TreeHead{Size: 3}
	logPub, logSigner, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	sth, err := th.Sign(logSigner)
	if err != nil {
		t.Fatal(err)
	}

	td := testData{
		sth:     sth,
		logPub:  logPub,
		logHash: crypto.HashBytes(logPub[:]),
	}

	origin := types.SigsumCheckpointOrigin(&logPub)

	for i := 0; i < count; i++ {
		pub, s, err := crypto.NewKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		cosignature, err := th.Cosign(s, origin, 0)
		if err != nil {
			t.Fatal(err)
		}

		td.cosignatures = append(td.cosignatures, cosignature)
		td.witnessKeys = append(td.witnessKeys, pub)
		td.witnessHashes = append(td.witnessHashes, crypto.HashBytes(pub[:]))
	}
	return td
}

func TestWitnessPolicy(t *testing.T) {
	td := newTestData(t, 6)

	// Four known witnesses, at least 3 cosignatures required.
	p, err := NewKofNPolicy([]crypto.PublicKey{td.logPub},
		td.witnessKeys[:4], 3)
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
		{"all cosignatures", []int{0, 1, 2, 3, 4}, -1, true},
		{"all cosignatures, one invalid", []int{0, 1, 2, 3, 4}, 2, true},
		{"three cosignatures, but one invalid", []int{0, 2, 3, 4}, 2, false},
	} {
		present := make(map[crypto.Hash]types.Cosignature)
		for _, i := range s.w {
			cs := td.cosignatures[i]
			if i == s.invalidate {
				cs.Signature[3] ^= 1
			}
			present[td.witnessHashes[i]] = cs
		}
		err := p.VerifyCosignedTreeHead(&td.logHash,
			&types.CosignedTreeHead{SignedTreeHead: td.sth, Cosignatures: present})
		if s.expectValid && err != nil {
			t.Errorf("%s: Failed on valid cth: %v", s.desc, err)
		}
		if !s.expectValid && err == nil {
			t.Errorf("%s: Expected error, but got none", s.desc)
		}
	}
}

func TestOneOfNWitnessPolicy(t *testing.T) {
	td := newTestData(t, 6)
	// Policy with 1-of-n everywhere, i.e., any witness is accepted.
	//
	//        q
	//       / \
	//     g0   g2
	//    / |   /|\
	//   w0 w1 w4|w5
	//          g1
	//          / \
	//         w2 w3
	p, err := NewPolicy(
		AddLog(&Entity{PublicKey: td.logPub}),
		AddWitness("w0", &Entity{PublicKey: td.witnessKeys[0]}),
		AddWitness("w1", &Entity{PublicKey: td.witnessKeys[1]}),
		AddGroup("g0", 1, []string{"w0", "w1"}),
		AddWitness("w2", &Entity{PublicKey: td.witnessKeys[2]}),
		AddWitness("w3", &Entity{PublicKey: td.witnessKeys[3]}),
		AddGroup("g1", 1, []string{"w2", "w3"}),
		AddWitness("w4", &Entity{PublicKey: td.witnessKeys[4]}),
		AddWitness("w5", &Entity{PublicKey: td.witnessKeys[5]}),
		AddGroup("g2", 1, []string{"g1", "w4", "w5"}),
		AddGroup("q", 1, []string{"g0", "g2"}),
		SetQuorum("q"))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.VerifyCosignedTreeHead(
		&td.logHash, &types.CosignedTreeHead{SignedTreeHead: td.sth}); err == nil {
		t.Errorf("1-of-n policy, no cosignatures: Expected error, got none")
	}
	// Exhaustive test, one bit per witness is 64 cases.
	for i := 1; i < 64; i++ {
		present := make(map[crypto.Hash]types.Cosignature)
		for j := 0; j < 6; j++ {
			if (i & (1 << j)) > 0 {
				present[td.witnessHashes[j]] = td.cosignatures[j]
			}
		}
		if err := p.VerifyCosignedTreeHead(
			&td.logHash, &types.CosignedTreeHead{
				SignedTreeHead: td.sth,
				Cosignatures:   present,
			}); err != nil {
			t.Errorf("1-of-n policy, failed for case %d: %v", i, err)
		}
	}
}
func TestTwoOfNWitnessPolicy(t *testing.T) {
	td := newTestData(t, 6)
	// Similar policy with 2-of-n everywhere.
	p, err := NewPolicy(
		AddLog(&Entity{PublicKey: td.logPub}),
		AddWitness("w0", &Entity{PublicKey: td.witnessKeys[0]}),
		AddWitness("w1", &Entity{PublicKey: td.witnessKeys[1]}),
		AddGroup("g0", 2, []string{"w0", "w1"}),
		AddWitness("w2", &Entity{PublicKey: td.witnessKeys[2]}),
		AddWitness("w3", &Entity{PublicKey: td.witnessKeys[3]}),
		AddGroup("g1", 2, []string{"w2", "w3"}),
		AddWitness("w4", &Entity{PublicKey: td.witnessKeys[4]}),
		AddWitness("w5", &Entity{PublicKey: td.witnessKeys[5]}),
		AddGroup("g2", 2, []string{"g1", "w4", "w5"}),
		AddGroup("q", 2, []string{"g0", "g2"}),
		SetQuorum("q"))
	if err != nil {
		t.Fatal(err)
	}
	// Exhaustive test, one bit per witness is 64 cases.
	for i := 0; i < 64; i++ {
		present := make(map[crypto.Hash]types.Cosignature)
		for j := 0; j < 6; j++ {
			if (i & (1 << j)) > 0 {
				present[td.witnessHashes[j]] = td.cosignatures[j]
			}
		}
		// Expected answer: We must have both groups g0 and
		// g2. For g0, we have must have both w0 and w1. For
		// g2, we have this truth table:
		truth := [16]bool{
			false, false, false, false, // both w4 and w5 missing
			false, false, false, true, // w4, valid if both w2, w3
			false, false, false, true, // w5, valid if both w2, w3
			true, true, true, true, // both of w4 and w5
		}
		expectValid := (i&3) == 3 && truth[i>>2]
		err := p.VerifyCosignedTreeHead(
			&td.logHash, &types.CosignedTreeHead{
				SignedTreeHead: td.sth,
				Cosignatures:   present,
			})
		if expectValid && err != nil {
			t.Errorf("2-of-n policy, failed for case %d: %v", i, err)
		}
		if !expectValid && err == nil {
			t.Errorf("2-of-n policy, expect error for case %d, got none", i)
		}
	}
}
