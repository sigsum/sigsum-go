package merkle

import (
	"bytes"
	"fmt"

	"sigsum.org/sigsum-go/pkg/crypto"
)

// VerifyConsistency verifies that a Merkle tree is consistent.  The algorithm
// used is in RFC 9162, §2.1.4.2.  It is the same proof technique as RFC 6962.
func VerifyConsistency(oldSize, newSize uint64, oldRoot, newRoot *crypto.Hash, path []crypto.Hash) error {
	// Step 0 (not in RFC 6962): support the easy cases of an empty proof
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

	// Step 1
	if len(path) == 0 {
		return fmt.Errorf("proof input is malformed: no path")
	}

	// Step2,
	if isPowerOfTwo(oldSize) {
		path = append([]crypto.Hash{*oldRoot}, path...)
	}

	// Step 3
	fn := oldSize - 1
	sn := newSize - 1

	// Step 4
	for isOdd(fn) {
		fn >>= 1
		sn >>= 1
	}

	// Step 5
	fr := path[0]
	sr := path[0]

	// Step 6
	for _, c := range path[1:] {
		// Step 6(a)
		if sn == 0 {
			return fmt.Errorf("proof input is malformed: reached root too soon")
		}

		// Step 6(b)
		if isOdd(fn) || fn == sn {
			// Step 6(b), i
			fr = HashInteriorNode(&c, &fr)
			// Step 6(b), ii
			sr = HashInteriorNode(&c, &sr)
			// Step 6(b), iii
			if isEven(fn) {
				for {
					fn >>= 1
					sn >>= 1

					if isOdd(fn) || fn == 0 {
						break
					}
				}
			}
		} else {
			// Step 6(b), i
			sr = HashInteriorNode(&sr, &c)
		}

		// Step 6(c)
		fn >>= 1
		sn >>= 1
	}

	// Step 7
	if sn != 0 {
		return fmt.Errorf("proof input is malformed: never reached the root")
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

	for sn := size - 1; fn < sn; path, fn, sn = path[1:], fn>>1, sn>>1 {
		if len(path) == 0 {
			return fmt.Errorf("proof input is malformed: path too short")
		}
		if isOdd(fn) {
			// Node on path is left sibling
			r = HashInteriorNode(&path[0], &r)
		} else {
			// Node on path is right sibling
			r = HashInteriorNode(&r, &path[0])
		}
	}

	// We have the right-most node, so all nodes left on the path
	// are left siblings, and there are no siblings at even
	// indices.
	for ; fn > 0; fn >>= 1 {
		if isOdd(fn) {
			if len(path) == 0 {
				return fmt.Errorf("proof input is malformed: path too short")
			}
			r = HashInteriorNode(&path[0], &r)
			path = path[1:]
		}
	}

	if len(path) > 0 {
		return fmt.Errorf("proof input is malformed: reached root too soon")
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

// Checks if num is a power of 2. It is required that num > 0.
func isPowerOfTwo(num uint64) bool {
	return (num & (num - 1)) == 0
}
