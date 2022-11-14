// package merkle provides hashing operations that can be used to verify a
// Sigsum log's Merkle tree.  The exact hash strategy is defined in RFC 6962.
package merkle

import (
	"bytes"
	"sigsum.org/sigsum-go/pkg/crypto"
)

type Prefix uint8

const (
	PrefixLeafNode Prefix = iota
	PrefixInteriorNode
)

func formatLeafNode(b []byte) []byte {
	prefixLeafNode := []byte{byte(PrefixLeafNode)}
	return bytes.Join([][]byte{prefixLeafNode, b}, nil)
}

func formatInternalNode(left, right *crypto.Hash) []byte {
	prefixInteriorNode := []byte{byte(PrefixInteriorNode)}
	return bytes.Join([][]byte{prefixInteriorNode, (*left)[:], (*right)[:]}, nil)
}

func HashLeafNode(leaf []byte) crypto.Hash {
	return crypto.HashBytes(formatLeafNode(leaf))
}

func HashInteriorNode(left, right *crypto.Hash) crypto.Hash {
	return crypto.HashBytes(formatInternalNode(left, right))
}
