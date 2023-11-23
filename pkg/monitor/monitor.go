package monitor

import (
	"context"
	"sync"
	"time"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

const (
	DefaultBatchSize     = 512
	DefaultQueryInterval = 10 * time.Minute
)

type MonitorState struct {
	TreeHead types.TreeHead
	// Index of next leaf to process.
	NextLeafIndex uint64
}

// TODO: Figure out the proper interface to the monitor. Are callbacks
// the right way, or should we instead have one or more channels to
// pass new data items and alerts? There may be concurrent callbacks,
// but not no concurrent callbacks referring to the same log.
type Callbacks interface {
	// Called when a log (identified by key hash) has a new tree
	// head. The state may be persisted by the application.
	NewTreeHead(logKeyHash crypto.Hash, state MonitorState, cosignedTreeHead types.CosignedTreeHead)
	// Called when there are new leaves with submit key of
	// interest. Includes only leaves with a known submit key, and
	// where signature and inclusion proof are valid.
	NewLeaves(logKeyHash crypto.Hash, state MonitorState, indices []uint64, leaves []types.Leaf)
	// Called on detected problems with the log or witnesses.
	Alert(logKeyHash crypto.Hash, e error)
}

type Config struct {
	QueryInterval time.Duration
	// Maximum number of leaves to request at a time
	BatchSize uint64
	// Keys of interest. If nil, all keys are of interest (but no
	// signatures are verified).
	SubmitKeys map[crypto.Hash]crypto.PublicKey
	Callbacks  Callbacks
}

func (c *Config) applyDefaults() Config {
	r := *c
	if r.QueryInterval <= 0 {
		r.QueryInterval = DefaultQueryInterval
	}
	if r.BatchSize == 0 {
		r.BatchSize = DefaultBatchSize
	}
	return r
}

func (c *Config) filterLeaves(
	leaves []types.Leaf, startIndex uint64, alertCallback func(*Alert)) ([]uint64, []types.Leaf) {
	if c.SubmitKeys == nil {
		indices := make([]uint64, len(leaves))
		for i := range indices {
			indices[i] = startIndex + uint64(i)
		}
		return indices, leaves
	}
	indices := []uint64{}
	matchedLeaves := []types.Leaf{}
	for i, leaf := range leaves {
		index := startIndex + uint64(i)
		if key, ok := c.SubmitKeys[leaf.KeyHash]; ok {
			if !leaf.Verify(&key) {
				// Indicates log is misbehaving.
				// Generate alert and continue
				// processing remaining leaves. This
				// is an issue where inconsistent
				// verification conditions could
				// matter, see
				// https://hdevalence.ca/blog/2020-10-04-its-25519am
				alertCallback(newAlert(AlertLogError, "invalid signature on leaf %d, keyhash %x", index, leaf.KeyHash))
			} else {
				matchedLeaves = append(matchedLeaves, leaf)
				indices = append(indices, index)
			}
		}
	}
	return indices, matchedLeaves
}

// Monitor a single sigsum log. A monitor program is expected to call
// this function in one goroutine per log it monitors.
func MonitorLog(ctx context.Context, client *monitoringLogClient,
	state MonitorState, c *Config) {
	config := c.applyDefaults()
	keyHash := crypto.HashBytes(client.logKey[:])
	for ctx.Err() == nil {
		updateCtx, _ := context.WithTimeout(ctx, config.QueryInterval)
		if state.TreeHead.Size == state.NextLeafIndex {
			cth, err := client.getTreeHead(ctx, &state.TreeHead)
			if err != nil {
				config.Callbacks.Alert(keyHash, err)
			} else if cth.Size > state.TreeHead.Size {
				state.TreeHead = cth.TreeHead
				config.Callbacks.NewTreeHead(keyHash, state, cth)
			}
		}
		for glState := (*getLeavesState)(nil); state.NextLeafIndex < state.TreeHead.Size; {
			end := state.TreeHead.Size
			if end-state.NextLeafIndex > config.BatchSize {
				end = state.NextLeafIndex + config.BatchSize
			}
			var allLeaves []types.Leaf
			var err error
			allLeaves, glState, err = client.getLeaves(ctx, glState, &state.TreeHead,
				requests.Leaves{StartIndex: state.NextLeafIndex, EndIndex: end})
			if err != nil {
				config.Callbacks.Alert(keyHash, err)
				break
			}
			indices, leaves := config.filterLeaves(allLeaves, state.NextLeafIndex, func(alert *Alert) {
				config.Callbacks.Alert(keyHash, err)
			})
			state.NextLeafIndex += uint64(len(allLeaves))
			config.Callbacks.NewLeaves(keyHash, state, indices, leaves)
		}
		// Waits until end of interval
		<-updateCtx.Done()
	}
}

// Runs monitor in the background, until ctx is cancelled.
func StartMonitoring(
	ctx context.Context, p *policy.Policy,
	config *Config,
	state map[crypto.Hash]MonitorState) <-chan struct{} {
	var wg sync.WaitGroup
	for _, l := range p.GetLogsWithUrl() {
		keyHash := crypto.HashBytes(l.PublicKey[:])
		initialState, ok := state[keyHash]
		if !ok {
			initialState = MonitorState{
				TreeHead:      types.NewEmptyTreeHead(),
				NextLeafIndex: 0,
			}
		}

		wg.Add(1)
		go func(l policy.Entity) {
			MonitorLog(ctx, newMonitoringLogClient(&l.PublicKey, l.URL), initialState, config)
			wg.Done()
		}(l)
	}
	ch := make(chan struct{})
	go func() {
		wg.Wait()
		close(ch)
	}()
	return ch
}
