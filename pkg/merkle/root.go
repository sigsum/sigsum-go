package merkle

import (
	"fmt"
	"sigsum.org/sigsum-go/pkg/crypto"
)

// State for computing the root hash of a merkle tree. To use, first
// call Add() on each leaf in sequence, then call Root() to compute
// the root hash.
type TreeStack struct {
	n uint
	// Stack of intermediate nodes. Represents hashes of subtrees of size 2^{k_0},
	// 2^{k_1}, 2^{k_2}, ..., such that k_0 > k_1 > k_2  > ..., and n = 2^{k_0} + 2^{k_1} + 2^{k_2} + ...
	stack []crypto.Hash
}

func (t *TreeStack) push(h *crypto.Hash) {
	t.stack = append(t.stack, *h)
}

func (t *TreeStack) top() *crypto.Hash {
	if len(t.stack) == 0 {
		panic(fmt.Errorf("stack is empty!"))
	}
	return &t.stack[len(t.stack)-1]
}

func (t *TreeStack) drop() {
	if len(t.stack) == 0 {
		panic(fmt.Errorf("stack is empty!"))
	}
	t.stack = t.stack[:len(t.stack)-1]
}

func (t *TreeStack) pop() crypto.Hash {
	if len(t.stack) == 0 {
		panic(fmt.Errorf("stack is empty!"))
	}
	h := *t.top()
	t.drop()
	return h
}

func (t *TreeStack) makeInterior(h *crypto.Hash) crypto.Hash {
	n := HashInteriorNode(t.top(), h)
	t.drop()
	return n
}

func (t *TreeStack) Add(leaf *crypto.Hash) {
	t.n++
	h := *leaf
	for i := t.n; (i & 1) == 0; i /= 2 {
		h = t.makeInterior(&h)
	}
	t.push(&h)
	if popcount(t.n) != len(t.stack) {
		panic(fmt.Errorf("internal error: stack size %d, tree size 0x%x", len(t.stack), t.n))
	}
}

func (t *TreeStack) Root() (crypto.Hash, error) {
	if t.n == 0 {
		return crypto.Hash{}, fmt.Errorf("tree is empty")
	}
	h := t.pop()

	for len(t.stack) > 0 {
		h = t.makeInterior(&h)
	}
	return h, nil
}

func popcount(n uint) int {
	c := 0
	for ; n > 0; n >>= 1 {
		c += int(n & 1)
	}
	return c
}
