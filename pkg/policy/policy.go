package policy

import (
	"fmt"
	"math/rand"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

type Entity struct {
	PublicKey crypto.Ed25519PublicKey
	URL       string
}

type Processor[T any] interface {
	ProcessWitness(kh crypto.Hash) T
	ProcessGroup(k int, members []T) T
}

type tree interface {
	// Do a depth-first traversal, invoking the Processor for each
	// group and witness in the tree. Ideally, this should be a
	// generic method, but that's not allowed on an interface.
	depthFirst(processor Processor[any]) any
}

type Policy struct {
	logs      map[crypto.Hash]Entity
	witnesses map[crypto.Hash]Entity
	quorum    tree
}

// processorWrapper implements the Processor[any] interface on top of
// a Processor[T]. The wrapper adds type conversions where needed.
type processorWrapper[T any] struct {
	processor Processor[T]
}

func (w processorWrapper[T]) ProcessWitness(kh crypto.Hash) any {
	return w.processor.ProcessWitness(kh)
}

func (w processorWrapper[T]) ProcessGroup(k int, members []any) any {
	typedMembers := make([]T, len(members))
	for i, m := range members {
		typedMembers[i] = m.(T)
	}
	return w.processor.ProcessGroup(k, typedMembers)
}

// Performs a depth-first traversal of the quorum tree.
func (p *Policy) ProcessQuorum[T any](processor Processor[T]) T {
	return p.quorum.depthFirst(processorWrapper[T]{processor}).(T)
}

// This processor evaluates if the quorum is satisfied, using bool
// values.
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
func (qp quorumProcessor) ProcessWitness(kh crypto.Hash) bool {
	_, ok := qp.verified[kh]
	return ok
}

func (_ quorumProcessor) ProcessGroup(k int, members []bool) bool {
	c := 0
	for _, m := range members {
		if m {
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
	if !p.ProcessQuorum(processor) {
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

func NewKofNPolicy(logs, witnesses []crypto.Ed25519PublicKey, k int) (*Policy, error) {
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
