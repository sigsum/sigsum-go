package merkle

import (
	"fmt"
	"math/bits"

	"sigsum.org/sigsum-go/pkg/crypto"
)

// Represents a compact range starting at index zero. See
// https://github.com/transparency-dev/merkle/blob/main/docs/compact_ranges.md
// for the general definition.
type compactRange []crypto.Hash

// Like append, returns the new range, but may also modify the input.
func (cr compactRange) extend(i uint64, h crypto.Hash,
	makeNode func(left, right *crypto.Hash) crypto.Hash) compactRange {
	for s := i + 1; len(cr) > 0 && isEven(s); s >>= 1 {
		h = makeNode(&cr[len(cr)-1], &h)
		cr = cr[:len(cr)-1]
	}
	return append(cr, h)
}

// Returns a compact range for leaves starting at index zero.
func newCompactRange(leaves []crypto.Hash) compactRange {
	cr := compactRange{}
	for i, leaf := range leaves {
		cr = cr.extend(uint64(i), leaf, HashInteriorNode)
	}
	return cr
}

func (cr compactRange) getRootHash() crypto.Hash {
	if len(cr) == 0 {
		return HashEmptyTree()
	}
	h := cr[len(cr)-1]
	for i := len(cr) - 1; i > 0; i-- {
		h = HashInteriorNode(&cr[i-1], &h)
	}
	return h
}

// Represents a tree of leaf hashes. Not concurrency safe; needs
// external synchronization.
type Tree struct {
	leafs []crypto.Hash
	// Maps leaf hash to index.
	leafIndex map[crypto.Hash]int
	// Compact range; hash of one power-of-two subtree per one-bit
	// in current size.
	cRange compactRange
}

func NewTree() Tree {
	return Tree{leafIndex: make(map[crypto.Hash]int)}
}

func (t *Tree) Size() uint64 {
	return uint64(len(t.leafs))
}

// Returns true if added, false for duplicates.
func (t *Tree) AddLeafHash(leafHash *crypto.Hash) bool {
	if _, ok := t.leafIndex[*leafHash]; ok {
		return false
	}
	h := *leafHash
	t.leafIndex[h] = len(t.leafs)
	t.leafs = append(t.leafs, h)
	t.cRange = t.cRange.extend(uint64(len(t.leafs))-1, h, HashInteriorNode)
	return true
}

func (t *Tree) GetLeafIndex(leafHash *crypto.Hash) (uint64, error) {
	if i, ok := t.leafIndex[*leafHash]; ok {
		return uint64(i), nil
	}
	return 0, fmt.Errorf("leaf hash not present")
}

func (t *Tree) GetRootHash() crypto.Hash {
	return t.cRange.getRootHash()
}

func rootOf(leaves []crypto.Hash) crypto.Hash {
	return newCompactRange(leaves).getRootHash()
}

func reversePath(p []crypto.Hash) []crypto.Hash {
	n := len(p)
	for i := 0; i < n-1-i; i++ {
		p[i], p[n-1-i] = p[n-1-i], p[i]
	}
	return p
}

// Produces inclusion path from root down (opposite to rfc 9162 order).
// cRange and size represent the larger tree, where leaves is a prefix.
func inclusion(leaves []crypto.Hash, m uint64, cRange []crypto.Hash, size uint64) []crypto.Hash {
	p := []crypto.Hash{}

	// Try reusing hashes of internal nodes on the cRange; useful
	// if m and len(leaves) are close to the end of the tree.
	for len(leaves) > 1 && len(cRange) > 1 {
		// Size of subtree represented by cRange[0]
		k := split(size)
		if m < k {
			// Could possibly use some other elements of
			// cRange, but it gets complicated.
			break
		}
		// k gives a valid split also for the subtree
		// for which we prove inclusion.
		p = append(p, cRange[0])
		cRange = cRange[1:]
		size -= k
		leaves = leaves[k:]
		m -= k
	}

	for len(leaves) > 1 {
		n := uint64(len(leaves))
		k := split(n)

		// We select the subtree which m is in, for further
		// processing, after adding the hash of the other
		// subtree to the path.
		if m < k {
			p = append(p, rootOf(leaves[k:]))
			leaves = leaves[:k]
		} else {
			p = append(p, rootOf(leaves[:k]))
			leaves = leaves[k:]
			m -= k
		}
	}
	return p
}

func (t *Tree) ProveInclusion(index, size uint64) ([]crypto.Hash, error) {
	if index >= size || size > t.Size() {
		return nil, fmt.Errorf("invalid argument index %d, size %d, tree %d", index, size, t.Size())
	}
	return reversePath(inclusion(t.leafs[:size], index, t.cRange, t.Size())), nil
}

// Based on RFC 9162, 2.1.4.1, but produces path in opposite order.
func consistency(leaves []crypto.Hash, m uint64, cRange []crypto.Hash, size uint64) []crypto.Hash {
	p := []crypto.Hash{}
	complete := true

	// Try reusing hashes of internal nodes on the cRange; useful
	// if m and len(leaves) are close to the end of the tree.
	for len(cRange) > 1 {
		n := uint64(len(leaves))
		if m == n {
			break
		}
		// Size of subtree represented by cRange[0]
		k := split(size)
		if m <= k {
			// Could possibly use some other elements of
			// cRange, but it gets complicated.
			break
		}
		// k gives a valid split also for the subtree
		// for which we prove consistency.
		p = append(p, cRange[0])
		cRange = cRange[1:]
		size -= k
		leaves = leaves[k:]
		m -= k
		complete = false
	}
	for {
		n := uint64(len(leaves))
		if m > n {
			panic(fmt.Errorf("internal error, m %d, n %d", m, n))
		}
		if m == n {
			if complete {
				return p
			}
			return append(p, rootOf(leaves))
		}
		k := split(n)
		if m <= k {
			p = append(p, rootOf(leaves[k:]))
			leaves = leaves[:k]
		} else {
			p = append(p, rootOf(leaves[:k]))
			leaves = leaves[k:]
			m -= k
			complete = false
		}
	}
}

func (t *Tree) ProveConsistency(m, n uint64) ([]crypto.Hash, error) {
	if n > t.Size() || m > n {
		return nil, fmt.Errorf("invalid argument m %d, n %d, tree %d", m, n, t.Size())
	}
	if m == 0 || m == n {
		return []crypto.Hash{}, nil
	}
	return reversePath(consistency(t.leafs[:n], m, t.cRange, t.Size())), nil
}

// Returns largest power of 2 smaller than n. Requires n >= 2.
func split(n uint64) uint64 {
	if n < 2 {
		panic(fmt.Errorf("internal error, can't split %d", n))
	}
	return uint64(1) << (bits.Len64(n-1) - 1)
}

func isEven(num uint64) bool {
	return (num & 1) == 0
}
