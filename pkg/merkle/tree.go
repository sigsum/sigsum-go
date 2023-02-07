package merkle

import (
	"fmt"
	"math/bits"

	"sigsum.org/sigsum-go/pkg/crypto"
)

// Represents a tree of leaf hashes. Not concurrency safe; needs
// external synchronization.
type Tree struct {
	leafs []crypto.Hash
	// Maps leaf hash to index.
	leafIndex map[crypto.Hash]int
	// Stack with hash of one power-of-two subtree per one-bit in
	// current size.
	stack []crypto.Hash
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

	for i := len(t.leafs); (i & 1) == 0; i >>= 1 {
		h = HashInteriorNode(&t.stack[len(t.stack)-1], &h)
		t.stack = t.stack[:len(t.stack)-1]
	}
	t.stack = append(t.stack, h)
	return true
}

func (t *Tree) GetLeafIndex(leafHash *crypto.Hash) (uint64, error) {
	if i, ok := t.leafIndex[*leafHash]; ok {
		return uint64(i), nil
	}
	return 0, fmt.Errorf("leaf hash not present")
}

func hashStack(stack []crypto.Hash) crypto.Hash {
	if len(stack) == 0 {
		panic(fmt.Errorf("internal error, empty stack"))
	}
	h := stack[len(stack)-1]
	for i := len(stack) - 1; i > 0; i-- {
		h = HashInteriorNode(&stack[i-1], &h)
	}
	return h
}

func (t *Tree) GetRootHash() crypto.Hash {
	if len(t.stack) == 0 {
		// Special case, all-zero hash
		return crypto.HashBytes([]byte{})
	}
	return hashStack(t.stack)
}

func rootOf(leaves []crypto.Hash) crypto.Hash {
	if len(leaves) == 0 {
		panic(fmt.Errorf("internal error"))
	}
	tree := NewTree()
	for _, leaf := range leaves {
		if !tree.AddLeafHash(&leaf) {
			panic(fmt.Errorf("internal error, unexpected duplicate"))
		}
	}
	return tree.GetRootHash()
}

func reversePath(p []crypto.Hash) []crypto.Hash {
	n := len(p)
	for i := 0; i < n-1-i; i++ {
		p[i], p[n-1-i] = p[n-1-i], p[i]
	}
	return p
}

// Produces inclusion path from root down (opposite to rfc 9162 order).
// Stack and size represent the larger tree, where leaves is a prefix.
func inclusion(leaves []crypto.Hash, m uint64, stack []crypto.Hash, size uint64) []crypto.Hash {
	p := []crypto.Hash{}

	// Try reusing hashes of internal nodes on the stack; useful
	// if m and len(leaves) are close to the end of the tree.
	for len(leaves) > 1 && len(stack) > 1 {
		// Size of subtree represented by stack[0]
		k := split(size)
		if m < k {
			// Could possibly use some other elements of
			// stack, but it gets complicated.
			break
		}
		// k gives a valid split also for the subtree
		// for which we prove inclusion.
		p = append(p, stack[0])
		stack = stack[1:]
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
	return reversePath(inclusion(t.leafs[:size], index, t.stack, t.Size())), nil
}

// Based on RFC 9161, 2.1.4.1, but produces path in opposite order.
func consistency(leaves []crypto.Hash, m uint64, stack []crypto.Hash, size uint64) []crypto.Hash {
	p := []crypto.Hash{}
	complete := true

	// Try reusing hashes of internal nodes on the stack; useful
	// if m and len(leaves) are close to the end of the tree.
	for len(stack) > 1 {
		n := uint64(len(leaves))
		if m == n {
			break
		}
		// Size of subtree represented by stack[0]
		k := split(size)
		if m <= k {
			// Could possibly use some other elements of
			// stack, but it gets complicated.
			break
		}
		// k gives a valid split also for the subtree
		// for which we prove consistency.
		p = append(p, stack[0])
		stack = stack[1:]
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
	if m == 0 || n > t.Size() || m >= n {
		return nil, fmt.Errorf("invalid argument m %d, n %d, tree %d", m, n, t.Size())
	}
	return reversePath(consistency(t.leafs[:n], m, t.stack, t.Size())), nil
}

// Returns largest power of 2 smaller than n. Requires n >= 2.
func split(n uint64) uint64 {
	if n < 2 {
		panic(fmt.Errorf("internal error, can't split %d", n))
	}
	return uint64(1) << (bits.Len64(n-1) - 1)
}
