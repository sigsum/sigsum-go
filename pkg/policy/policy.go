package policy

import (
	"fmt"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

type entity struct {
	pubKey crypto.PublicKey
	// Add URL, to interact with entity?
}

// The method gets a set of witnesses for which a cosignature was
// verified, and returns whether or not they are sufficient.
type Quorum interface {
	IsQuorum(map[crypto.Hash]struct{}) bool
}

type Policy struct {
	logs      map[crypto.Hash]entity
	witnesses map[crypto.Hash]entity
	quorum    Quorum
}

func (p *Policy) VerifyCosignedTreeHead(logKeyHash *crypto.Hash,
	cth *types.CosignedTreeHead) error {
	log, ok := p.logs[*logKeyHash]
	if !ok {
		return fmt.Errorf("unknown log")
	}
	if !cth.Verify(&log.pubKey) {
		return fmt.Errorf("invalid log signature")
	}
	verified := make(map[crypto.Hash]struct{})
	failed := 0
	for _, cs := range cth.Cosignatures {
		if witness, ok := p.witnesses[cs.KeyHash]; ok {
			if cs.Verify(&witness.pubKey, logKeyHash, &cth.TreeHead) {
				verified[cs.KeyHash] = struct{}{}
			} else {
				failed++
			}
		}
	}
	if !p.quorum.IsQuorum(verified) {
		return fmt.Errorf("not enough cosignatures, total: %d, verified: %d, failed to verify: %d", len(cth.Cosignatures), len(verified), failed)
	}
	return nil
}

type quorumSingle struct {
	w crypto.Hash
}

func (q *quorumSingle) IsQuorum(verified map[crypto.Hash]struct{}) bool {
	_, ok := verified[q.w]
	return ok
}

type quorumKofN struct {
	subQuorums []Quorum
	k          int
}

func (q *quorumKofN) IsQuorum(verified map[crypto.Hash]struct{}) bool {
	c := 0
	for _, sq := range q.subQuorums {
		if sq.IsQuorum(verified) {
			c++
		}
	}
	return c >= q.k
}

func newEmptyPolicy() *Policy {
	return &Policy{
		logs:      make(map[crypto.Hash]entity),
		witnesses: make(map[crypto.Hash]entity),
	}
}

func (p *Policy) addLog(log *entity) (crypto.Hash, error) {
	h := crypto.HashBytes(log.pubKey[:])
	if _, dup := p.logs[h]; dup {
		return crypto.Hash{}, fmt.Errorf("duplicate log: %x\n", log.pubKey)
	}
	p.logs[h] = *log
	return h, nil
}

func (p *Policy) addWitness(witness *entity) (crypto.Hash, error) {
	h := crypto.HashBytes(witness.pubKey[:])
	if _, dup := p.logs[h]; dup {
		return crypto.Hash{}, fmt.Errorf("duplicate log: %x\n", witness.pubKey)
	}
	p.witnesses[h] = *witness
	return h, nil
}

func NewKofNPolicy(logs, witnesses []crypto.PublicKey, k int) (*Policy, error) {
	if k > len(witnesses) {
		return nil, fmt.Errorf("invalid policy k (%d) > n (%d)\n", k, len(witnesses))
	}
	p := newEmptyPolicy()

	for _, l := range logs {
		if _, err := p.addLog(&entity{l}); err != nil {
			return nil, err
		}
	}

	subQuorums := []Quorum{}

	for _, w := range witnesses {
		h, err := p.addWitness(&entity{w})
		if err != nil {
			return nil, err
		}
		subQuorums = append(subQuorums, &quorumSingle{h})
	}
	p.quorum = &quorumKofN{subQuorums: subQuorums, k: k}
	return p, nil
}
