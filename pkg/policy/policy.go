package policy

import (
	"fmt"
	"math/rand"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

type Entity struct {
	PublicKey crypto.PublicKey
	URL       string
}

type Processor interface {
	ProcessWitness(kh crypto.Hash) any
	ProcessGroup(k int, members []any) any
}

type tree interface {
	// Do a depth-first traversal, invoking the Processor for each
	// group and witness in the tree.
	depthFirst(processor Processor) any
}

type Policy struct {
	logs      map[crypto.Hash]Entity
	witnesses map[crypto.Hash]Entity
	quorum    tree
}

// Performs a depth-first traversal of the quorum tree.
func (p *Policy) ProcessQuorum(processor Processor) any {
	return p.quorum.depthFirst(processor)
}

// This processor evaluates if the quorum is satisfied, using bool
// values everywhere the Processor interface uses any.
type quorumProcessor struct {
	// The set of witnesses for which a cosignature was verified.
	verified map[crypto.Hash]struct{}
}

func newQuorumProcessor() quorumProcessor {
	return quorumProcessor{
		verified: make(map[crypto.Hash]struct{}),
	}
}

func (qp quorumProcessor) count() int {
	return len(qp.verified)
}

func (qp quorumProcessor) addVerifiedWitness(kh crypto.Hash) {
	qp.verified[kh] = struct{}{}
}

// Implement Processor interface
func (qp quorumProcessor) ProcessWitness(kh crypto.Hash) any {
	_, ok := qp.verified[kh]
	return ok
}

func (_ quorumProcessor) ProcessGroup(k int, members []any) any {
	c := 0
	for _, m := range members {
		if m.(bool) {
			c++
		}
	}
	return c >= k
}

func (p *Policy) VerifyCosignedTreeHead(logKeyHash *crypto.Hash,
	cth *types.CosignedTreeHead) error {
	log, ok := p.logs[*logKeyHash]
	if !ok {
		return fmt.Errorf("unknown log")
	}
	if !cth.Verify(&log.PublicKey) {
		return fmt.Errorf("invalid log signature")
	}
	origin := types.SigsumCheckpointOrigin(&log.PublicKey)
	processor := newQuorumProcessor()
	failed := 0
	for keyHash, cs := range cth.Cosignatures {
		if witness, ok := p.witnesses[keyHash]; ok {
			if cs.Verify(&witness.PublicKey, origin, &cth.TreeHead) {
				processor.addVerifiedWitness(keyHash)
			} else {
				failed++
			}
		}
	}
	if !p.ProcessQuorum(processor).(bool) {
		return fmt.Errorf("not enough cosignatures, total: %d, verified: %d, failed to verify: %d",
			len(cth.Cosignatures), processor.count(), failed)
	}
	return nil
}

func randomizeEntities(m map[crypto.Hash]Entity, filter func(e *Entity) bool) []Entity {
	entities := make([]Entity, 0, len(m))
	for _, entity := range m {
		if filter(&entity) {
			entities = append(entities, entity)
		}
	}
	// Return in randomized order.
	rand.Shuffle(len(entities), func(i, j int) { entities[i], entities[j] = entities[j], entities[i] })
	return entities
}
func entitiesWithURL(m map[crypto.Hash]Entity) []Entity {
	return randomizeEntities(m, func(e *Entity) bool { return len(e.URL) > 0 })
}
func entitiesAll(m map[crypto.Hash]Entity) []Entity {
	return randomizeEntities(m, func(_ *Entity) bool { return true })
}

// Returns all logs, in randomized order.
func (p *Policy) GetLogs() []Entity {
	return entitiesAll(p.logs)
}

// Returns all witnesses, in randomized order.
func (p *Policy) GetWitnesses() []Entity {
	return entitiesAll(p.witnesses)
}

// Returns all logs with url specified, in randomized order.
func (p *Policy) GetLogsWithUrl() []Entity {
	return entitiesWithURL(p.logs)
}

// Returns all witnesses with url specified, in randomized order.
func (p *Policy) GetWitnessesWithUrl() []Entity {
	return entitiesWithURL(p.witnesses)
}

func NewPolicy(settings ...Setting) (*Policy, error) {
	b := newBuilder()
	for _, s := range settings {
		if err := s.apply(b); err != nil {
			return nil, err
		}
	}
	return b.finish()
}

func NewKofNPolicy(logs, witnesses []crypto.PublicKey, k int) (*Policy, error) {
	var settings []Setting

	if k > len(witnesses) {
		return nil, fmt.Errorf("invalid policy k (%d) > n (%d)\n", k, len(witnesses))
	}
	for _, l := range logs {
		settings = append(settings, AddLog(&Entity{PublicKey: l}))
	}

	if len(witnesses) > 0 {
		// TODO: Extend the builder interface so that a policy can be
		// defined without using names to refer between groups and
		// witnesses?
		var names []string
		for i, w := range witnesses {
			name := fmt.Sprintf("w%d", i)
			settings = append(settings, AddWitness(name, &Entity{PublicKey: w}))
			names = append(names, name)
		}
		settings = append(settings, AddGroup("g", k, names))
		settings = append(settings, SetQuorum("g"))
	} else {
		settings = append(settings, SetQuorum("none"))
	}
	return NewPolicy(settings...)
}
