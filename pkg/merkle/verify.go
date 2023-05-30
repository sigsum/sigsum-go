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

// Represents the hashes associated with a continuous "compact range".
// The indices represented by the range are implicit, since they vary
// as algorithms use this structure at different levels of the tree.
type compactRange struct {
	stack []crypto.Hash
	empty int
}

func newCompactRange(hash *crypto.Hash) *compactRange {
	return &compactRange{stack: []crypto.Hash{*hash}, empty: 0}
}

// Extend the range to the right, with an entry at index n - 1.
func (r *compactRange) addRight(i uint64, hash *crypto.Hash) {
	if len(r.stack) == r.empty {
		panic("range empty")
	}
	h := *hash
	// TODO: XXX We have to somehow record the height of subtrees.
	// E.g., if we have a stack of two entries and add an entry
	// with index 3, we should reduce once to create the interior
	// node representing the range [2, 4). But we don't know if
	// the first entry on the stack represents [0,2), in which
	// case we should reduce once more, or just [1,2) (a leaf
	// hash).
	for s := i + 1; isEven(s) && len(r.stack) > r.empty; s >>= 1 {
		h = HashInteriorNode(&r.stack[len(r.stack)-1], &h)
		r.stack = r.stack[:len(r.stack)-1]
	}
	r.stack = append(r.stack, h)
}

// Extend the range to the left, with an entry at index i.
func (r *compactRange) addLeft(i uint64, hash *crypto.Hash) {
	if len(r.stack) == r.empty {
		panic("range empty")
	}
	h := *hash
	for ; isEven(i) && len(r.stack) > r.empty; i >>= 1 {
		h = HashInteriorNode(&h, &r.stack[r.empty])
		r.empty++
	}
	if r.empty > 0 {
		r.empty--
	} else {
		// Reallocate with more space at the start.
		r.stack = append([]crypto.Hash{h}, r.stack...)
	}
	r.stack[r.empty] = h
}

// Assumes that range has been extended all the way to index zero.
func (r *compactRange) rootHash() crypto.Hash {
	h := r.stack[len(r.stack)-1]
	for i := len(r.stack) - 1; i > r.empty; i-- {
		h = HashInteriorNode(&r.stack[i-1], &h)
	}
	return h
}

// VerifyInclusion verifies that something is in a Merkle tree.  The algorithm
// used is in RFC 9162, §2.1.3.2.  It is the same proof technique as RFC 6962.
func VerifyInclusion(leaf *crypto.Hash, index, size uint64, root *crypto.Hash, path []crypto.Hash) error {
	if index >= size {
		return fmt.Errorf("proof input is malformed: index out of range")
	}

	// Each iteration of the loop eliminates the bottom layer of
	// the tree. fn is the index in the tree for the hash of
	// interest, r, and sn is the index of the last node in the
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

	cRange := newCompactRange(leaf)

	fn := index
	sn := size - 1

	for fn < sn {
		var s *crypto.Hash
		if len(path) == 0 {
			return fmt.Errorf("proof input is malformed: path too short")
		}
		s, path = &path[0], path[1:]
		if isOdd(fn) {
			// Node on path is left sibling
			cRange.addLeft(fn-1, s)
		} else {
			// Node on path is left sibling
			cRange.addRight(fn+1, s)
		}
		// Drop bottom layer of the tree, continue proving
		// inclusion for the internal node constructed above.
		fn >>= 1
		sn >>= 1
	}

	// We have the right-most node, so all nodes left on the path are left siblings.
	for fn > 0 {
		if isOdd(fn) {
			var s *crypto.Hash
			if len(path) == 0 {
				return fmt.Errorf("proof input is malformed: path too short")
			}
			s, path = &path[0], path[1:]
			cRange.addLeft(fn-1, s)
		}
		fn >>= 1
	}
	if len(path) > 0 {
		return fmt.Errorf("proof input is malformed: reached root too soon")
	}

	if cRange.rootHash() != *root {
		return fmt.Errorf("invalid proof: root mismatch")
	}
	return nil
}

// VerifyBatchInclusion verifies a consecutive sequence of leaves are
// included in a Merkle tree. The algorithm is an extension of the
// inclusion proof in RFC 9162, §2.1.3.2, using inclusion proofs for
// the first and last (inclusive) leaves in the sequence.

// In case the leaf sequence extends all the way to the last leaf of
// the tree, the correspondign inclusion proof is nott needed and can
// be omitted.

// TODO: Reduce duplication with VerifyInclusion; the latter could be a simple wrapper calling the more general function.
func VerifyInclusionBatch(leaves []crypto.Hash, index, size uint64, root *crypto.Hash, startPath []crypto.Hash, endPath []crypto.Hash) error {
	if len(leaves) == 0 {
		return fmt.Errorf("invalid input, empty leaf sequence")
	}
	if index + uint64(len(leaves)) > size {
		return fmt.Errorf("index out of range")
	}

	cRange := newCompactRange(&leaves[0])
	for i := 1; i < len(leaves); i++ {
		cRange.addRight(index + uint64(i), &leaves[i])
	}

	fn := index
	en := index + uint64(len(leaves)) - 1
	sn := size - 1

//	fmt.Printf("XXX crange: %x\n", *cRange)
//	fmt.Printf("XXX root: %x\n", *root)

	for en < sn {
		if len(startPath) == 0 {
			return fmt.Errorf("proof input is malformed: startPath too short")
		}
		if len(endPath) == 0 {
			return fmt.Errorf("proof input is malformed: endPath too short")
		}
		// Note that we may have fn == en; in that case, one
		// of the cases apply, and the paths should be equal.
		if isOdd(fn) {
			// Node on path is left sibling
			cRange.addLeft(fn - 1, &startPath[0])
		} else { /* Just ignore? */ }

		if isEven(en) {
			// Node on path is right sibling
			cRange.addRight(en + 1, &endPath[0])
		} else { /* Just ignore? */ }

		startPath = startPath[1:]
		endPath = endPath[1:]
		fn >>= 1
		en >>= 1
		sn >>= 1
	}

	// Range is extended to the end. Keep extending to the left.
	for fn < sn {
		if len(startPath) == 0 {
			return fmt.Errorf("proof input is malformed: startPath too short")
		}
		if isOdd(fn) {
			cRange.addLeft(fn-1, &startPath[0])
		}
		startPath = startPath[1:]
		fn >>= 1
		sn >>= 1
	}

	// Keep extending to the left, but path no longer has any
	// right siblings.
	for fn > 0 {
		if isOdd(fn) {
			if len(startPath) == 0 {
				return fmt.Errorf("proof input is malformed: path too short")
			}
			cRange.addLeft(fn-1, &startPath[0])
			startPath = startPath[1:]
		}
		fn >>= 1
	}

	fmt.Printf("XXX final crange: %x\n", *cRange)
	if cRange.rootHash() != *root {
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
