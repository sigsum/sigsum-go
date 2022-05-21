// package merkle provides hashing operations that can be used to verify a
// Sigsum log's Merkle tree.  The exact hash strategy is defined in RFC 6962.
package merkle

import (
	"bytes"
	"crypto/sha256"
	"fmt"
)

type Prefix uint8

const (
	PrefixLeafNode Prefix = iota
	PrefixInteriorNode
)

var (
	prefixLeafNode     = []byte{byte(PrefixLeafNode)}
	prefixInteriorNode = []byte{byte(PrefixInteriorNode)}
)

const (
	HashSize = sha256.Size
)

type Hash [HashSize]byte

func HashFn(b []byte) *Hash {
	var ret Hash
	h := sha256.Sum256(b)
	copy(ret[:], h[:])
	return &ret
}

func HashLeafNode(leaf []byte) *Hash {
	var ret Hash
	h := sha256.New()
	h.Write(prefixLeafNode)
	h.Write(leaf)
	copy(ret[:], h.Sum(nil))
	return &ret
}

func HashInteriorNode(left, right Hash) *Hash {
	var ret Hash
	h := sha256.New()
	h.Write(prefixInteriorNode)
	h.Write(left[:])
	h.Write(right[:])
	copy(ret[:], h.Sum(nil))
	return &ret
}

// VerifyConsistency verifies that a Merkle tree is consistent.  The algorithm
// used is in RFC 9162, §2.1.4.2.  It is the same proof technique as RFC 6962.
func VerifyConsistency(oldSize, newSize uint64, oldRoot, newRoot Hash, path []Hash) error {
	// Step 1
	if len(path) == 0 {
		return fmt.Errorf("proof input is malformed: no path")
	}

	// Step2
	if pow2(oldSize) {
		path = append([]Hash{oldRoot}, path...)
	}

	// Step 3
	fn := oldSize - 1
	sn := newSize - 1

	// Step 4
	for lsb(fn) {
		fn = rshift(fn)
		sn = rshift(sn)
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
		if lsb(fn) || fn == sn {
			// Step 6(b), i
			fr = *HashInteriorNode(c, fr)
			// Step 6(b), ii
			sr = *HashInteriorNode(c, sr)
			// Step 6(b), iii
			if !lsb(fn) {
				for {
					fn = rshift(fn)
					sn = rshift(sn)

					if lsb(fn) || fn == 0 {
						break
					}
				}
			}
		} else {
			// Step 6(b), i
			sr = *HashInteriorNode(sr, c)
		}

		// Step 6(c)
		fn = rshift(fn)
		sn = rshift(sn)
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
func VerifyInclusion(leaf Hash, index, size uint64, root Hash, path []Hash) error {
	// Step 1
	if index >= size {
		return fmt.Errorf("proof input is malformed: index out of range")
	}

	// Step 2
	fn := index
	sn := size - 1

	// Step 3
	r := leaf

	// Step 4
	for _, p := range path {
		// Step 4(a)
		if sn == 0 {
			return fmt.Errorf("proof input is malformed: reached root too soon")
		}

		// Step 4(b)
		if lsb(fn) || fn == sn {
			// Step 4(b), i
			r = *HashInteriorNode(p, r)

			// Step 4(b), ii
			if !lsb(fn) {
				for {
					fn = rshift(fn)
					sn = rshift(sn)

					if lsb(fn) || fn == 0 {
						break
					}
				}
			}
		} else {
			// Step 4(b), i
			r = *HashInteriorNode(r, p)
		}

		// Step 4(c)
		fn = rshift(fn)
		sn = rshift(sn)
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

// lsb outputs true if the least significant bit is set
func lsb(num uint64) bool {
	return (num & 1) != 0
}

// pow2 outputs true if the number is a power of 2
func pow2(num uint64) bool {
	return (num & (num - 1)) == 0
}

// rshift returns the right-shifted number
func rshift(num uint64) uint64 {
	return num >> 1
}
