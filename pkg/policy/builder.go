package policy

import (
	"fmt"

	"sigsum.org/sigsum-go/pkg/crypto"
)

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

// Represents a policy being built.
type builder struct {
	names map[string]Quorum
	// Names that have already been used as group members, and
	// must not be used again. The map value is the name of parent
	// group, for error messages.
	usedNames map[string]string
	logs      map[crypto.Hash]Entity
	witnesses map[crypto.Hash]Entity
	quorum    Quorum
}

func newBuilder() *builder {
	return &builder{
		names:     map[string]Quorum{ConfigNone: &quorumKofN{}},
		usedNames: make(map[string]string),
		logs:      make(map[crypto.Hash]Entity),
		witnesses: make(map[crypto.Hash]Entity),
	}
}

func (b *builder) finish() (*Policy, error) {
	if b.quorum == nil {
		return nil, fmt.Errorf("no quorum defined")
	}
	return &Policy{
		logs:      b.logs,
		witnesses: b.witnesses,
		quorum:    b.quorum,
	}, nil
}

type Setting interface {
	apply(*builder) error
}

func (b *builder) ifdef(name string) bool {
	_, ok := b.names[name]
	return ok
}

// Looks up the name of a group member. On success, marks name as used
// so that it cannot be used as a member a second time.
func (b *builder) lookupMember(member, parent string) (Quorum, error) {
	if other, ok := b.usedNames[member]; ok {
		return nil, fmt.Errorf("group/witness %q is already a member of %q", member, other)
	}
	if quorum, ok := b.names[member]; ok {
		b.usedNames[member] = parent
		return quorum, nil
	}
	return nil, fmt.Errorf("undefined name: %q", member)
}

type addLog struct {
	entity Entity
}

func (l *addLog) apply(b *builder) error {
	h := crypto.HashBytes(l.entity.PublicKey[:])
	if _, dup := b.logs[h]; dup {
		return fmt.Errorf("duplicate log: %x\n", l.entity.PublicKey)
	}
	b.logs[h] = l.entity
	return nil
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
	h := crypto.HashBytes(w.entity.PublicKey[:])
	if _, dup := b.witnesses[h]; dup {
		return fmt.Errorf("duplicate witness: %x\n", w.entity.PublicKey)
	}
	b.witnesses[h] = w.entity
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
		return fmt.Errorf("group %q: invalid threshold k = %d for n = %d", g.name, g.threshold, len(g.members))
	}
	subQuorums := []Quorum{}

	for _, member := range g.members {
		q, err := b.lookupMember(member, g.name)
		if err != nil {
			return err
		}
		subQuorums = append(subQuorums, q)
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
	if b.quorum != nil {
		return fmt.Errorf("quorum can only be set once")
	}

	if q, ok := b.names[s.name]; ok {
		b.quorum = q
	} else {
		return fmt.Errorf("undefined name %q", s.name)
	}
	return nil
}

func SetQuorum(name string) Setting {
	return &setQuorum{name}
}
