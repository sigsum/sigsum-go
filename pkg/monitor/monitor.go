package monitor

import (
	"context"
	"fmt"
	"time"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

const (
	batchSize = 512
)

// TODO: Figure out the proper interface to the monitor. Are callbacks
// the right way, or should we instead have one or more channels to
// pass new data items and alerts?
type Callbacks interface {
	// Called when a log (identified by key hash) has a new tree
	// head; application can use this to persist the tree head.
	// TODO: Also include cosignatures?
	NewTreeHead(logKeyHash crypto.Hash, signedTreeHead types.SignedTreeHead)
	// Called when there are new leaves with submit key of
	// interest. Includes only leaves with a known submit key, and
	// where signature and inclusion proof are valid.
	// TODO: Also pass along index for each leaf?
	NewLeaves(logKeyHash crypto.Hash, leaves []types.Leaf)
	Alert(logKeyHash crypto.Hash, e error)
}

// State for monitoring a single sigsum log. A monitor program is
// expected to have one instance and one goroutine per log it
// monitors.
type Monitor struct {
	// Keys of interest. If nil, all keys are of interest (but no
	// signatures are verified).
	submitKeys map[crypto.Hash]crypto.PublicKey

	client *monitoringLogClient

	// TODO: This mutated field implies that this struct isn't
	// concurrency safe. Which is no big problem, since it is used
	// only by the goroutine spawned by the Run method. But
	// consider removing the field here, and handle the the latest
	// tree head as an input argument, and return value, for the
	// Update method.
	treeHead types.TreeHead
	// Index of next leaf to process.
	leafPos uint64
}

func (m *Monitor) filterLeaves(leaves []types.Leaf) ([]types.Leaf, error) {
	if m.submitKeys == nil {
		return leaves, nil
	}
	matchedLeaves := []types.Leaf{}
	for _, leaf := range leaves {
		if key, ok := m.submitKeys[leaf.KeyHash]; ok {
			if !leaf.Verify(&key) {
				// Indicates log is misbehaving.
				// TODO: Report error, but continue processing other leaves?
				return nil, newAlert(AlertLogError, "invalid leaf signature, keyhash %x", leaf.KeyHash)
			}
			matchedLeaves = append(matchedLeaves, leaf)
		}
	}
	return matchedLeaves, nil
}

func (m *Monitor) Run(ctx context.Context, interval time.Duration, callbacks Callbacks) {
	keyHash := crypto.HashBytes(m.client.logKey[:])
	for ctx.Err() == nil {
		updateCtx, _ := context.WithTimeout(ctx, interval)
		if m.treeHead.Size == m.leafPos {
			cth, err := m.client.getTreeHead(ctx, &m.treeHead)
			if err != nil {
				callbacks.Alert(keyHash, err)
			} else if cth.Size > m.treeHead.Size {
				callbacks.NewTreeHead(keyHash, cth)
				m.treeHead = cth.TreeHead
			}
		}
		for state := (*getLeavesState)(nil); m.leafPos < m.treeHead.Size; {
			end := m.treeHead.Size
			if end-m.leafPos > batchSize {
				end = m.leafPos + batchSize
			}
			var leaves []types.Leaf
			var err error
			leaves, state, err = m.client.getLeaves(ctx, state, &m.treeHead,
				requests.Leaves{StartIndex: m.leafPos, EndIndex: end})
			if err != nil {
				callbacks.Alert(keyHash, err)
			}
			nextPos := m.leafPos + uint64(len(leaves))
			leaves, err = m.filterLeaves(leaves)
			if err != nil {
				callbacks.Alert(keyHash, err)
			}
			if leaves != nil {
				// TODO: Also pass nextPos, for
				// application to be able to persist
				// it.
				callbacks.NewLeaves(keyHash, leaves)
			}
			m.leafPos = nextPos
		}
		// Waits until end of interval
		<-updateCtx.Done()
	}
}

// Runs monitor in the background, until ctx is cancelled.
func StartMonitoring(
	ctx context.Context, p *policy.Policy,
	interval time.Duration,
	submitKeys map[crypto.Hash]crypto.PublicKey,
	state map[crypto.Hash]types.SignedTreeHead,
	callbacks Callbacks) error {
	monitors := []Monitor{}
	for _, l := range p.GetLogsWithUrl() {
		keyHash := crypto.HashBytes(l.PublicKey[:])
		monitor := Monitor{
			submitKeys: submitKeys,
			client:     newMonitoringLogClient(&l.PublicKey, l.URL),
		}
		if sth, ok := state[keyHash]; ok {
			if !sth.Verify(&l.PublicKey) {
				return fmt.Errorf("invalid signature in old state for log %q", keyHash)
			}
			monitor.treeHead = sth.TreeHead
			// TODO: include in the state mapping.
			monitor.leafPos = monitor.treeHead.Size
		} else {
			monitor.treeHead = types.NewEmptyTreeHead()
			monitor.leafPos = 0
		}
		monitors = append(monitors, monitor)
	}
	for _, m := range monitors {
		go m.Run(ctx, interval, callbacks)
	}
	return nil
}
