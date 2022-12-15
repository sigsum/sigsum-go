package merkle

import (
	"testing"

	"encoding/binary"
	"math/bits"
	"sigsum.org/sigsum-go/pkg/crypto"
)

func TestSize(t *testing.T) {
	hashes := newLeaves(5)

	tree := NewTree()
	for i, h := range hashes {
		if !tree.AddLeafHash(&h) {
			t.Fatalf("AddLeafHash failed at size %d", tree.Size())
		}
		if got, want := tree.Size(), uint64(i)+1; got != want {
			t.Errorf("unexepcted size, got %d, want %d", got, want)
		}
	}
}

func TestGetLeafIndex(t *testing.T) {
	hashes := newLeaves(5)

	tree := NewTree()
	for _, h := range hashes {
		if !tree.AddLeafHash(&h) {
			t.Fatalf("AddLeafHash failed at size %d", tree.Size())
		}
	}
	for i, h := range hashes {
		got, err := tree.GetLeafIndex(&h)
		if err != nil {
			t.Errorf("GetLeafIndex failed at index %d: %v", i, err)
		} else if got != uint64(i) {
			t.Errorf("incorrect index, got %d, want %d", got, i)
		}
	}
}

func TestInternal(t *testing.T) {
	tree := NewTree()
	for _, h := range newLeaves(100) {
		if !tree.AddLeafHash(&h) {
			t.Fatalf("AddLeafHash failed at size %d", tree.Size())
		}
		if len(tree.leafs) != len(tree.leafIndex) {
			t.Fatalf("invalid state: %d leafs, %d index entries",
				len(tree.leafs), len(tree.leafIndex))
		}
		if popc := bits.OnesCount(uint(len(tree.leafs))); popc != len(tree.stack) {
			t.Fatalf("internal error: popc %d, len 0x%x", popc, len(tree.stack))
		}
	}
}

func TestGetRootHash(t *testing.T) {
	hashes := newLeaves(5)
	h01 := HashInteriorNode(&hashes[0], &hashes[1])
	h23 := HashInteriorNode(&hashes[2], &hashes[3])
	h0123 := HashInteriorNode(&h01, &h23)

	tree := NewTree()
	for i, want := range []crypto.Hash{
		crypto.Hash{},
		hashes[0],
		h01,
		HashInteriorNode(&h01, &hashes[2]),
		h0123,
		HashInteriorNode(&h0123, &hashes[4]),
	} {
		if tree.Size() < uint64(i) {
			if !tree.AddLeafHash(&hashes[tree.Size()]) {
				t.Fatalf("AddLeafHash failed at size %d", tree.Size())
			}
		}
		if got := tree.GetRootHash(); got != want {
			t.Errorf("bad root hash for size %d\n  got: %x\n want: %x",
				i, got, want)
		}
	}
}

func TestInclusion(t *testing.T) {
	hashes := newLeaves(5)
	h01 := HashInteriorNode(&hashes[0], &hashes[1])
	h23 := HashInteriorNode(&hashes[2], &hashes[3])
	h0123 := HashInteriorNode(&h01, &h23)

	tree := NewTree()
	for _, h := range hashes {
		if !tree.AddLeafHash(&h) {
			t.Fatalf("AddLeafHash failed at size %d", tree.Size())
		}
	}

	// Inclusion path for index i and size 5.
	for i, p := range [][]crypto.Hash{
		[]crypto.Hash{hashes[1], h23, hashes[4]},
		[]crypto.Hash{hashes[0], h23, hashes[4]},
		[]crypto.Hash{hashes[3], h01, hashes[4]},
		[]crypto.Hash{hashes[2], h01, hashes[4]},
		[]crypto.Hash{h0123},
	} {
		if proof, err := tree.ProveInclusion(uint64(i), 5); err != nil || !pathEqual(proof, p) {
			if err != nil {
				t.Fatalf("ProveInclusion %d, 5 failed: %v", i, err)
			}
			t.Errorf("unexpected inclusion path\n  got: %x\n want: %x\n",
				proof, p)
		}
	}
}

func TestInclusionValid(t *testing.T) {
	hashes := newLeaves(100)

	rootHashes := []crypto.Hash{}
	tree := NewTree()
	for _, h := range hashes {
		if !tree.AddLeafHash(&h) {
			t.Fatalf("AddLeafHash failed at size %d", tree.Size())
		}
		rootHashes = append(rootHashes, tree.GetRootHash())
	}
	for i := 0; i < len(hashes); i++ {
		for n := i + 1; n <= len(hashes); n++ {
			proof, err := tree.ProveInclusion(uint64(i), uint64(n))
			if err != nil {
				t.Fatalf("ProveInclusion %d, %d failed: %v", i, n, err)
			}
			if err := VerifyInclusion(&hashes[i], uint64(i), uint64(n), &rootHashes[n-1], proof); err != nil {
				t.Errorf("inclusion proof not valid, i %d, n %d: %v\n  proof: %x\n",
					i, n, err, proof)
			}
		}
	}
}

func TestConsistency(t *testing.T) {
	hashes := newLeaves(7)
	h01 := HashInteriorNode(&hashes[0], &hashes[1])
	h23 := HashInteriorNode(&hashes[2], &hashes[3])
	h0123 := HashInteriorNode(&h01, &h23)
	h45 := HashInteriorNode(&hashes[4], &hashes[5])
	h456 := HashInteriorNode(&h45, &hashes[6])

	tree := NewTree()
	for _, h := range hashes {
		if !tree.AddLeafHash(&h) {
			t.Fatalf("AddLeafHash failed at size %d", tree.Size())
		}
	}
	for _, table := range []struct {
		m    uint64
		n    uint64
		path []crypto.Hash // nil for expected error
	}{
		{3, 7, []crypto.Hash{hashes[2], hashes[3], h01, h456}},
		{4, 7, []crypto.Hash{h456}},
		{6, 7, []crypto.Hash{h45, hashes[6], h0123}},
		{6, 8, nil},
		{7, 6, nil},
		{0, 6, nil},
	} {
		proof, err := tree.ProveConsistency(table.m, table.n)
		if table.path == nil {
			// Expect error
			if err == nil {
				t.Errorf("expected error, got consistency path: %x", proof)
			}
		} else {
			if err != nil {
				t.Errorf("ProveConsistency %d, %d failed: %v", table.m, table.n, err)
			} else if !pathEqual(proof, table.path) {
				t.Errorf("unexpected inclusion path m %d, n %d\n  got: %x\n want: %x\n",
					table.m, table.n, proof, table.path)
			}
		}
	}
}

func TestConsistencyValid(t *testing.T) {
	hashes := newLeaves(100)

	rootHashes := []crypto.Hash{}
	tree := NewTree()
	for _, h := range hashes {
		if !tree.AddLeafHash(&h) {
			t.Fatalf("AddLeafHash failed at size %d", tree.Size())
		}
		rootHashes = append(rootHashes, tree.GetRootHash())
	}

	for m := 1; m < len(hashes); m++ {
		for n := m + 1; n <= len(hashes); n++ {
			proof, err := tree.ProveConsistency(uint64(m), uint64(n))
			if err != nil {
				t.Fatalf("ProveConsistency %d, %d failed: %v", m, n, err)
			}
			if err := VerifyConsistency(
				uint64(m), uint64(n),
				&rootHashes[m-1], &rootHashes[n-1], proof); err != nil {
				t.Errorf("consistency proof not valid, m %d, n %d: %v\n  proof: %x\n",
					m, n, err, proof)
			}
		}
	}
}

func newLeaves(n int) []crypto.Hash {
	hashes := make([]crypto.Hash, n)
	for i := 0; i < n; i++ {
		var blob [8]byte
		binary.BigEndian.PutUint64(blob[:], uint64(i))
		hashes[i] = HashLeafNode(blob[:])
	}
	return hashes
}

func pathEqual(a, b []crypto.Hash) bool {
	if len(a) != len(b) {
		return false
	}
	for i, h := range a {
		if h != b[i] {
			return false
		}
	}
	return true
}
