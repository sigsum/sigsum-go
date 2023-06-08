package merkle

import (
	"bytes"
	"fmt"
	"math/bits"

	"sigsum.org/sigsum-go/pkg/crypto"
)

func pathLength(index, size uint64) int {
	// k is the number of lowend bits that differ between fn and
	// sn, i.e., number of iterations until fn == sn.
	k := bits.Len64(index ^ (size - 1))
	return k + bits.OnesCount64(index>>k)
}

// VerifyConsistency verifies that a Merkle tree is consistent.  The algorithm
// used is in RFC 9162, §2.1.4.2.  It is the same proof technique as RFC 6962.
func VerifyConsistency(oldSize, newSize uint64, oldRoot, newRoot *crypto.Hash, path []crypto.Hash) error {
	// First handle the easy cases where an empty proof is valid.
	if oldSize == newSize {
		// Consistent if and only if roots are equal.
		// Require empty path.
		if len(path) > 0 {
			return fmt.Errorf("non-empty consistency path for trees of equal size")
		}
		if *oldRoot != *newRoot {
			return fmt.Errorf("consistency check failed: same size, but roots differ")
		}
		return nil
	}
	if oldSize == 0 {
		// Anything is consistent with the empty tree.
		// Require empty path.
		if len(path) > 0 {
			return fmt.Errorf("non-empty consistency path for empty old tree")
		}
		if *oldRoot != HashEmptyTree() {
			return fmt.Errorf("unexpected root hash for the empty tree")
		}
		return nil
	}

	// The last leaf of the old tree is at index fn. Eliminate
	// bottom layers of the tree, until fn points at a subtree
	// that is a left child; that subtree is included as-is also
	// in the new tree, and that is the starting point for the
	// traversal.
	trimBits := bits.TrailingZeros64(oldSize) // Ones of oldSize - 1
	fn := (oldSize - 1) >> trimBits
	sn := (newSize - 1) >> trimBits

	wantLength := pathLength(fn, sn+1)
	if fn > 0 {
		wantLength++
	}
	if len(path) != wantLength {
		return fmt.Errorf("proof input is malformed: path length %d, should be %d", len(path), wantLength)
	}

	// If fn == 0, we start at the oldRoot, otherwise, the
	// starting point is the first element of the supplied path.
	var fr crypto.Hash
	if fn == 0 {
		fr = *oldRoot
	} else {
		fr, path = path[0], path[1:]
	}
	sr := fr

	for ; sn > 0; fn, sn = fn>>1, sn>>1 {
		if isOdd(fn) {
			// Node on path is left sibling
			fr = HashInteriorNode(&path[0], &fr)
			sr = HashInteriorNode(&path[0], &sr)
			path = path[1:]
		} else if fn < sn {
			// Node on path is right sibling for the larger tree.
			sr = HashInteriorNode(&sr, &path[0])
			path = path[1:]
		}
	}
	if len(path) > 0 {
		panic("internal error: left over path elements")
	}

	if !bytes.Equal(fr[:], oldRoot[:]) {
		return fmt.Errorf("invalid proof: old root mismatch")
	}
	if !bytes.Equal(sr[:], newRoot[:]) {
		return fmt.Errorf("invalid proof: new root mismatch")
	}
	return nil
}

// VerifyInclusion verifies that something is in a Merkle tree. The
// algorithm used is equivalent to the one in in RFC 9162, §2.1.3.2.
// Note that with index == 0, size == 1, the empty path is considered
// a valid inclusion proof, and inclusion means that *leaf == *root.
func VerifyInclusion(leaf *crypto.Hash, index, size uint64, root *crypto.Hash, path []crypto.Hash) error {
	if index >= size {
		return fmt.Errorf("proof input is malformed: index out of range")
	}

	if got, want := len(path), pathLength(index, size); got != want {
		return fmt.Errorf("proof input is malformed: path length %d, should be %d", got, want)
	}

	// Each iteration of the loop eliminates the bottom layer of
	// the tree. fn is the index in the tree for the hash of
	// interest, r. sn is the index of the last node in the
	// tree. All leaf nodes, in particular the final one with
	// index sn, are considered to be at the bottom layer, but
	// possibly with the parent located more than one layer above.
	// E.g., the tree with 3 leaves:
	//
	//     o      Root node
	//    / \
	//   o   \
	//  / \   \
	// o   o   o  The three leaf nodes
	// 0   1   2

	r := *leaf
	fn := index

	for sn := size - 1; sn > 0; fn, sn = fn>>1, sn>>1 {
		if isOdd(fn) {
			// Node on path is left sibling
			r = HashInteriorNode(&path[0], &r)
			path = path[1:]
		} else if fn < sn {
			// Node on path is right sibling
			r = HashInteriorNode(&r, &path[0])
			path = path[1:]
		}
	}
	if len(path) > 0 {
		panic("internal error: left over path elements")
	}

	if r != *root {
		return fmt.Errorf("invalid proof: root mismatch")
	}
	return nil
}

func isOdd(num uint64) bool {
	return (num & 1) != 0
}

func isEven(num uint64) bool {
	return (num & 1) == 0
}
