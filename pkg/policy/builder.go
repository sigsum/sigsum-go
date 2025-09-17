package policy

import (
	"fmt"
)

// Represents a policy being built.
type builder struct {
	// TODO: Move mappings and update logic here, and delete
	// methods like Policy.addWitness.
	policy *Policy
	names  map[string]Quorum
}

func newBuilder() *builder {
	return &builder{
		policy: newEmptyPolicy(),
		names:  map[string]Quorum{ConfigNone: &quorumKofN{}},
	}
}

func (b *builder) finish() (*Policy, error) {
	if b.policy.quorum == nil {
		return nil, fmt.Errorf("no quorum defined")
	}
	return b.policy, nil
}

type Setting interface {
	apply(*builder) error
}

func (b *builder) ifdef(name string) bool {
	_, ok := b.names[name]
	return ok
}

type addLog struct {
	entity Entity
}

func (l *addLog) apply(b *builder) error {
	_, err := b.policy.addLog(&l.entity)
	return err
}

func AddLog(entity *Entity) Setting {
	return &addLog{*entity}
}

type addWitness struct {
	name   string
	entity Entity
}

func (w *addWitness) apply(b *builder) error {
	if b.ifdef(w.name) {
		return fmt.Errorf("duplicate name: %q", w.name)
	}
	h, err := b.policy.addWitness(&w.entity)
	if err != nil {
		return err
	}
	b.names[w.name] = &quorumSingle{h}
	return nil
}

func AddWitness(name string, entity *Entity) Setting {
	return &addWitness{
		name:   name,
		entity: *entity,
	}
}

type addGroup struct {
	name      string
	threshold int
	members   []string
}

func (g *addGroup) apply(b *builder) error {
	if b.ifdef(g.name) {
		return fmt.Errorf("duplicate name %q", g.name)
	}
	if g.threshold < 1 || g.threshold > len(g.members) {
		return fmt.Errorf("invalid threshold for group: %q", g.name)
	}
	subQuorums := []Quorum{}
	// TODO: Warn or fail if there's overlap between group members?
	for _, member := range g.members {
		if q, ok := b.names[member]; ok {
			subQuorums = append(subQuorums, q)
		} else {
			return fmt.Errorf("undefined name: %q", member)
		}
	}
	b.names[g.name] = &quorumKofN{subQuorums: subQuorums, k: g.threshold}
	return nil
}

func AddGroup(name string, threshold int, members []string) Setting {
	return &addGroup{
		name:      name,
		threshold: threshold,
		members:   members, // Note shallow copy.
	}
}

type setQuorum struct {
	name string
}

func (s *setQuorum) apply(b *builder) error {
	if b.policy.quorum != nil {
		return fmt.Errorf("quorum can only be set once")
	}

	if q, ok := b.names[s.name]; ok {
		b.policy.quorum = q
	} else {
		return fmt.Errorf("undefined name %q", s.name)
	}
	return nil
}

func SetQuorum(name string) Setting {
	return &setQuorum{name}
}
