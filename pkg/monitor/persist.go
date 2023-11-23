package monitor

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/dchest/safefile"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
)

// TODO: Document storage of state properly. A directory with one file
// per log, with hex keyhash as filename. Each file contains a signed
// tree head, a newline, and a line next_leaf_index=NUMBER.

func (s *MonitorState) FromASCII(r io.Reader) error {
	p := ascii.NewParser(r)

	if err := s.TreeHead.Parse(&p); err != nil {
		return err
	}
	if err := p.GetEmptyLine(); err != nil {
		return fmt.Errorf("missing leaf index part: %v", err)
	}

	var err error
	s.NextLeafIndex, err = p.GetInt("next_leaf_index")
	if err != nil {
		return err
	}
	return p.GetEOF()
}

func (s *MonitorState) ToASCII(w io.Writer) error {
	if err := s.TreeHead.ToASCII(w); err != nil {
		return err
	}
	// Empty line as separator.
	if _, err := fmt.Fprint(w, "\n"); err != nil {
		return err
	}
	return ascii.WriteInt(w, "next_leaf_index", s.NextLeafIndex)
}

type StateDirectory struct {
	directory string
}

func NewStateDirectory(directory string) *StateDirectory {
	return &StateDirectory{directory}
}

func (d *StateDirectory) ReadState(keyHash crypto.Hash) (MonitorState, error) {
	fileName := fmt.Sprintf("%s/%x", d.directory, keyHash)
	f, err := os.Open(fileName)
	if err != nil {
		return MonitorState{}, err
	}
	defer f.Close()
	var state MonitorState
	if err := state.FromASCII(f); err != nil {
		return MonitorState{}, err
	}
	return state, nil
}

func (d *StateDirectory) ReadStates(logKeys []crypto.PublicKey) (map[crypto.Hash]MonitorState, error) {
	// Require that directory exists.
	stat, err := os.Stat(d.directory)
	if err != nil {
		return nil, fmt.Errorf("monitor state directory %q doesn't exist: %v", d.directory, err)
	}
	if !stat.IsDir() {
		return nil, fmt.Errorf("monitor state directory %q refers to a non-directory", d.directory)
	}

	m := make(map[crypto.Hash]MonitorState)
	for _, key := range logKeys {
		keyHash := crypto.HashBytes(key[:])
		state, err := d.ReadState(keyHash)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// Do nothing.
				continue
			}
			return nil, err
		}
		m[keyHash] = state
	}
	return m, nil
}

func (d *StateDirectory) WriteState(keyHash crypto.Hash, state MonitorState) error {
	fileName := fmt.Sprintf("%s/%x", d.directory, keyHash)
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
