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

// VerifyInclusion verifies that something is in a Merkle tree.  The algorithm
// used is in RFC 9162, §2.1.3.2.  It is the same proof technique as RFC 6962.
func VerifyInclusion(leaf *crypto.Hash, index, size uint64, root *crypto.Hash, path []crypto.Hash) error {
	// Step 1
	if index >= size {
		return fmt.Errorf("proof input is malformed: index out of range")
	}

	// Step 2
	fn := index
	sn := size - 1

	// Step 3
	r := *leaf

	// Step 4
	for _, p := range path {
		// Step 4(a)
		if sn == 0 {
			return fmt.Errorf("proof input is malformed: reached root too soon")
		}

		// Step 4(b)
		if isOdd(fn) || fn == sn {
			// Step 4(b), i
			r = HashInteriorNode(&p, &r)

			// Step 4(b), ii
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
			// Step 4(b), i
			r = HashInteriorNode(&r, &p)
		}

		// Step 4(c)
		fn >>= 1
		sn >>= 1
	}

	// Step 5
	if sn != 0 {
		return fmt.Errorf("proof input is malformed: never reached the root")
	}
	if !bytes.Equal(r[:], root[:]) {
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
