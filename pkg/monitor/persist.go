package monitor

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

// TODO: Document storage of state properly. A directory with one file
// per log, with hex keyhash as filename. Each file contains a signed
// tree head, a newline, and a line nect_leaf_index=NUMBER.

func parseMonitorState(r io.Reader) (types.SignedTreeHead, uint64, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return types.SignedTreeHead{}, 0, fmt.Errorf("reading monitor state failed: %v", err)
	}
	parts := bytes.Split(data, []byte{'\n', '\n'})
	if len(parts) != 2 {
		return types.SignedTreeHead{}, 0, fmt.Errorf("invalid monitor state")
	}
	// Extend slice to get back a single newline.
	parts[0] = parts[0][:len(parts[0])+1]

	var sth types.SignedTreeHead
	if err := sth.FromASCII(bytes.NewBuffer(parts[0])); err != nil {
		return types.SignedTreeHead{}, 0, err
	}
	parser := ascii.NewParser(bytes.NewBuffer(parts[1]))
	nextLeafIndex, err := parser.GetInt("next_leaf_index")
	if err != nil {
		return types.SignedTreeHead{}, 0, err
	}
	return sth, nextLeafIndex, parser.GetEOF()
}

type PersistedState struct {
	directory string
}

func (s PersistedState) ReadState(logKeys []crypto.PublicKey) (map[crypto.Hash]MonitorState, error) {
	// Require that directory exists.
	stat, err := os.Stat(s.directory)
	if err != nil {
		return nil, fmt.Errorf("monitor state directory doesn't exist: %v", err)
	}
	if !stat.IsDir() {
		return nil, fmt.Errorf("monitor state directory %q refers to a non-directory", s.directory)
	}

	m := make(map[crypto.Hash]MonitorState)
	for _, key := range logKeys {
		keyHash := crypto.HashBytes(key[:])
		fname := fmt.Sprintf("%s/%x", s.directory, keyHash)
		err := func() error {
			f, err := os.Open(fname)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					// Do nothing.
					return nil
				}
				return err
			}
			defer f.Close()
			sth, nextLeafIndex, err := parseMonitorState(f)
			if err != nil {
				return err
			}
			if !sth.Verify(&key) {
				return fmt.Errorf("invalid tree head signature in monitor state")
			}
			m[keyHash] = MonitorState{TreeHead: sth.TreeHead, NextLeafIndex: nextLeafIndex}
			return nil
		}()
		if err != nil {
			return nil, err
		}
	}
	return m, nil
}
