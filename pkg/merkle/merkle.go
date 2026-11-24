// package merkle provides hashing operations that can be used to verify a
// Sigsum log's Merkle tree.  The exact hash strategy is defined in RFC 6962.
package merkle

import (
	"bytes"
	"sigsum.org/sigsum-go/v2/pkg/crypto"
)

type Prefix uint8

const (
	PrefixLeafNode Prefix = iota
	PrefixInteriorNode
)

type TreeHead struct {
	Size     uint64
	RootHash crypto.Hash
}

func NewEmptyTreeHead() TreeHead {
	return TreeHead{Size: 0, RootHash: HashEmptyTree()}
}

func HashLeafNode(leaf []byte) crypto.Hash {
	return crypto.HashBytes(formatLeafNode(leaf))
}

func HashInteriorNode(left, right *crypto.Hash) crypto.Hash {
	return crypto.HashBytes(formatInternalNode(left, right))
}

func HashEmptyTree() crypto.Hash {
	return crypto.HashBytes([]byte{})
}

func formatLeafNode(b []byte) []byte {
	prefixLeafNode := []byte{byte(PrefixLeafNode)}
	return bytes.Join([][]byte{prefixLeafNode, b}, nil)
}

func formatInternalNode(left, right *crypto.Hash) []byte {
	prefixInteriorNode := []byte{byte(PrefixInteriorNode)}
	return bytes.Join([][]byte{prefixInteriorNode, (*left)[:], (*right)[:]}, nil)
}
