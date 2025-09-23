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

// The method gets a set of witnesses for which a cosignature was
// verified, and returns whether or not they are sufficient.
type Quorum interface {
	IsQuorum(map[crypto.Hash]struct{}) bool
}

type Policy struct {
	logs      map[crypto.Hash]Entity
	witnesses map[crypto.Hash]Entity
	quorum    Quorum
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
	verified := make(map[crypto.Hash]struct{})
	failed := 0
	for keyHash, cs := range cth.Cosignatures {
		if witness, ok := p.witnesses[keyHash]; ok {
			if cs.Verify(&witness.PublicKey, origin, &cth.TreeHead) {
				verified[keyHash] = struct{}{}
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

func randomizeEntities(m map[crypto.Hash]Entity) []Entity {
	entities := make([]Entity, 0, len(m))
	for _, entity := range m {
		if len(entity.URL) > 0 {
			entities = append(entities, entity)
		}
	}
	// Return in randomized order.
	rand.Shuffle(len(entities), func(i, j int) { entities[i], entities[j] = entities[j], entities[i] })
	return entities
}

// Returns all logs with url specified, in randomized order.
func (p *Policy) GetLogsWithUrl() []Entity {
	return randomizeEntities(p.logs)
}

// Returns all witnesses with url specified, in randomized order.
func (p *Policy) GetWitnessesWithUrl() []Entity {
	return randomizeEntities(p.witnesses)
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
