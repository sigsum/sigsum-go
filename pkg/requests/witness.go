package requests

import (
	"fmt"
	"io"
	"strings"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/checkpoint"
	"sigsum.org/sigsum-go/pkg/types"
)

type AddCheckpoint struct {
	OldSize    uint64
	Proof      types.ConsistencyProof
	Checkpoint checkpoint.Checkpoint
}

func (req *AddCheckpoint) FromASCII(r io.Reader) error {
	p := ascii.NewLineReader(r)

	s, err := p.GetLine()
	if err != nil {
		return err
	}
	s, found := strings.CutPrefix(s, "old ")
	if !found {
		return fmt.Errorf("invalid add-checkpoint request, invalid old line: %q", s)
	}
	req.OldSize, err = ascii.IntFromDecimal(s)
	if err != nil {
		return err
	}

	// Parse proof lines.
	if emptyLine, err := req.Proof.ParseBase64(&p); err != nil {
		return err
	} else if !emptyLine {
		return fmt.Errorf("invalid add-checkpoint request: %v", err)
	}

	if err := req.Checkpoint.Parse(&p); err != nil {
		return err
	}

	if req.OldSize > req.Checkpoint.TreeHead.Size {
		return fmt.Errorf("invalid request, old_size(%d) > size(%d)",
			req.OldSize, req.Checkpoint.TreeHead.Size)
	}
	// Check for empty/non-empty consistency proof.
	if req.OldSize == req.Checkpoint.TreeHead.Size || req.OldSize == 0 {
		if len(req.Proof.Path) > 0 {
			return fmt.Errorf("invalid add-checkpoint request, expected empty consistency proof")
		}
	} else if len(req.Proof.Path) == 0 {
		return fmt.Errorf("invalid add-checkpoint request, consistency proof missing")
	}
	return nil
}

func (req *AddCheckpoint) ToASCII(w io.Writer) error {
	if _, err := fmt.Fprintf(w, "old %d\n", req.OldSize); err != nil {
		return err
	}
	if err := req.Proof.ToBase64(w); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "\n"); err != nil {
		return err
	}
	return req.Checkpoint.ToASCII(w)
}
