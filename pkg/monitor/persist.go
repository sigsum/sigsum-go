package monitor

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/dchest/safefile"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/types"
)

// TODO: Document storage of state properly. A directory with one file
// per log, with hex keyhash as filename. Each file contains a signed
// tree head, a newline, and a line next_leaf_index=NUMBER.

// Similar to MonitorState, but also inludes the treehead signature.
type storedMonitorState struct {
	sth types.SignedTreeHead
	// Index of next leaf to process.
	nextLeafIndex uint64
}

func (s *storedMonitorState) FromASCII(r io.Reader) error {
	p := ascii.NewParser(r)

	if err := s.sth.Parse(&p); err != nil {
		return err
	}
	if err := p.GetEmptyLine(); err != nil {
		return fmt.Errorf("missing leaf index part: %v", err)
	}

	var err error
	s.nextLeafIndex, err = p.GetInt("next_leaf_index")
	if err != nil {
		return err
	}
	return p.GetEOF()
}

func (s *storedMonitorState) ToASCII(w io.Writer) error {
	if err := s.sth.ToASCII(w); err != nil {
		return err
	}
	// Empty line as separator.
	if _, err := fmt.Fprint(w, "\n"); err != nil {
		return err
	}
	return ascii.WriteInt(w, "next_leaf_index", s.nextLeafIndex)
}

type PersistedState struct {
	directory string
	// Protects access to the map. We allow concurrent updates for
	// distinct logs, but for each particular log, callbacks must
	// be sequential.
	mu sync.Mutex
	m  map[crypto.Hash]storedMonitorState
}

func NewPersistedState(directory string, logKeys []crypto.PublicKey) (*PersistedState, error) {
	// Require that directory exists.
	stat, err := os.Stat(directory)
	if err != nil {
		return nil, fmt.Errorf("monitor state directory doesn't exist: %v", err)
	}
	if !stat.IsDir() {
		return nil, fmt.Errorf("monitor state directory %q refers to a non-directory", directory)
	}

	m := make(map[crypto.Hash]storedMonitorState)
	for _, key := range logKeys {
		keyHash := crypto.HashBytes(key[:])
		fileName := fmt.Sprintf("%s/%x", directory, keyHash)
		err := func() error {
			f, err := os.Open(fileName)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					// Do nothing.
					return nil
				}
				return err
			}
			defer f.Close()
			var state storedMonitorState
			if err := state.FromASCII(f); err != nil {
				return err
			}
			if !state.sth.Verify(&key) {
				return fmt.Errorf("invalid tree head signature in monitor state")
			}
			m[keyHash] = state
			return nil
		}()
		if err != nil {
			return nil, fmt.Errorf("failed to read file %q: %w", fileName, err)
		}
	}
	return &PersistedState{directory: directory, m: m}, nil
}

func (s *PersistedState) GetInitialState() map[crypto.Hash]MonitorState {
	m := make(map[crypto.Hash]MonitorState)
	s.mu.Lock()
	defer s.mu.Unlock()

	for h, s := range s.m {
		m[h] = MonitorState{TreeHead: s.sth.TreeHead, NextLeafIndex: s.nextLeafIndex}
	}
	return m
}

func (s *PersistedState) WrapCallbacks(callbacks Callbacks) Callbacks {
	return &persistingCallbacks{state: s, callbacks: callbacks}
}

func (s *PersistedState) updateTreeHead(keyHash *crypto.Hash, sth *types.SignedTreeHead) *storedMonitorState {
	s.mu.Lock()
	defer s.mu.Unlock()

	if state, ok := s.m[*keyHash]; ok {
		if sth.Size <= state.sth.Size {
			if sth.Size < state.sth.Size {
				log.Error("monitor: Invalid tree head update, ignoring: key hash: %x, new size (%d), < old size (%d)",
					*keyHash, sth.Size, state.sth.Size)
			}
			return nil
		}
		state.sth = *sth
		s.m[*keyHash] = state
		return &state
	}
	state := storedMonitorState{sth: *sth, nextLeafIndex: 0}
	s.m[*keyHash] = state
	return &state
}

func (s *PersistedState) updateNextLeafIndex(keyHash *crypto.Hash, nextLeafIndex uint64) *storedMonitorState {
	s.mu.Lock()
	defer s.mu.Unlock()

	if state, ok := s.m[*keyHash]; ok {
		if nextLeafIndex > state.sth.Size {
			log.Error("monitor: Invalid leaf index update, ignoring: key hash: %x, new index (%d) > tree size (%d)",
				*keyHash, nextLeafIndex, state.sth.Size)
			return nil
		}
		if nextLeafIndex <= state.nextLeafIndex {
			if nextLeafIndex < state.nextLeafIndex {
				log.Error("monitor: Invalid leaf index update, ignoring: key hash: %x, new index (%d) < old index (%d)",
					*keyHash, nextLeafIndex, state.nextLeafIndex)
			}
			return nil
		}
		state.nextLeafIndex = nextLeafIndex
		s.m[*keyHash] = state
		return &state
	}
	log.Error("monitor: Invalid leaf index update, treehead unknown: key hash: %x, new index (%d)",
		*keyHash, nextLeafIndex)
	return nil
}

func (s *PersistedState) writeState(keyHash *crypto.Hash, state *storedMonitorState) error {
	fileName := fmt.Sprintf("%s/%x", s.directory, *keyHash)
	f, err := safefile.Create(fileName, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := state.ToASCII(f); err != nil {
		return err
	}
	// Atomically replace old file with new.
	return f.Commit()
}

type persistingCallbacks struct {
	state     *PersistedState
	callbacks Callbacks
}

func (c *persistingCallbacks) NewTreeHead(logKeyHash crypto.Hash, sth types.SignedTreeHead) {
	c.callbacks.NewTreeHead(logKeyHash, sth)
	if newState := c.state.updateTreeHead(&logKeyHash, &sth); newState != nil {
		c.state.writeState(&logKeyHash, newState)
	}
}
func (c *persistingCallbacks) NewLeaves(logKeyHash crypto.Hash, nextLeafIndex uint64, indices []uint64, leaves []types.Leaf) {
	c.callbacks.NewLeaves(logKeyHash, nextLeafIndex, indices, leaves)
	if newState := c.state.updateNextLeafIndex(&logKeyHash, nextLeafIndex); newState != nil {
		c.state.writeState(&logKeyHash, newState)
	}
}
func (c *persistingCallbacks) Alert(logKeyHash crypto.Hash, e error) {
	c.callbacks.Alert(logKeyHash, e)
}
