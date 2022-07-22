package leaf

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/http"
	"time"

	"git.sigsum.org/sigsum-go/pkg/merkle"
	"git.sigsum.org/sigsum-go/pkg/requests"
	"git.sigsum.org/sigsum-go/pkg/types"
)

type worker struct {
	Config
	inCh  chan *event // events that received 202
	outCh chan *event // events that received status 2XX
}

type event struct {
	start time.Time // time that request started
	end   time.Time // time that request ended with 2XX

	req    *http.Request // prepared add-leaf request
	got200 bool          // true if 200 response
	got202 bool          // true if at least one 202 responses

	num3xx uint64 // number of encountered 3xx before 2XX
	num4xx uint64 // number of encountered 4xx before 2XX
	num5xx uint64 // number of encountered 5xx before 2XX
}

func (w *worker) submit(ctx context.Context) error {
	data := make([]byte, 40)
	if _, err := rand.Read(data); err != nil {
		return fmt.Errorf("generate data: %v", err)
	}

	ctr := uint64(0)
	for {
		ctr += 1
		binary.BigEndian.PutUint64(data[:8], ctr)
		req, err := w.newRequest(merkle.HashFn(data))
		if err != nil {
			return err
		}

		ev := event{req: req, start: time.Now()}
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(w.Wait):
			}

			if err := w.doRequest(&ev); err == nil {
				break // success
			}
		}

		select {
		case w.outCh <- &ev:
		default:
			return fmt.Errorf("out channel is full")
		}
	}
}

func (w *worker) check(ctx context.Context) error {
	// setup a backoff mechanism that doesn't block
	next := make(chan struct{}, 1)
	backoff := func() {
		time.Sleep(w.backoff)
		next <- struct{}{}
	}
	next <- struct{}{}
	defer func() {
		<-next // empty channel before closing
		defer close(next)
	}()

	evs := make([]*event, 0, w.maxEvents)
	for {
		if len(evs) == w.maxEvents {
			return fmt.Errorf("checker has too many queued events: %d", w.maxEvents)
		}

		select {
		case <-ctx.Done():
			return nil
		case ev := <-w.inCh:
			evs = append(evs, ev)
			continue
		case <-next:
			if len(evs) == 0 {
				go backoff()
				continue
			}
		}

		if err := w.doRequest(evs[0]); err != nil {
			go backoff()
			continue
		}
		next <- struct{}{} // no backoff after success

		select {
		case w.outCh <- evs[0]:
		default:
			return fmt.Errorf("out channel is full")
		}
		evs = evs[1:]
	}
}

func (w *worker) newRequest(msg *merkle.Hash) (*http.Request, error) {
	stm := types.Statement{
		ShardHint: uint64(time.Now().Unix()),
		Checksum:  *merkle.HashFn(msg[:]),
	}
	sig, err := stm.Sign(w.signer)
	if err != nil {
		return nil, err
	}
	leaf := requests.Leaf{
		ShardHint:  stm.ShardHint,
		Message:    *msg,
		Signature:  *sig,
		PublicKey:  w.pub,
		DomainHint: w.DomainHint,
	}
	buf := bytes.NewBuffer(nil)
	if err := leaf.ToASCII(buf); err != nil {
		return nil, fmt.Errorf("serialize leaf request: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, w.url, buf)
	if err != nil {
		return nil, fmt.Errorf("create http request: %v", err)
	}
	return req, nil
}

func (w *worker) doRequest(ev *event) error {
	rsp, err := w.cli.Do(ev.req)
	if err != nil {
		return err
	}
	defer rsp.Body.Close()

	if rsp.StatusCode == http.StatusOK {
		ev.got200 = true
		ev.end = time.Now()
		return nil
	} else if rsp.StatusCode == http.StatusAccepted {
		if !ev.got202 {
			ev.got202 = true
			ev.end = time.Now()
			return nil // first 202 response
		}
	} else if rsp.StatusCode >= 300 && rsp.StatusCode < 400 {
		ev.num3xx += 1
	} else if rsp.StatusCode >= 400 && rsp.StatusCode < 500 {
		ev.num4xx += 1
	} else if rsp.StatusCode >= 500 && rsp.StatusCode < 600 {
		ev.num5xx += 1
	}
	return fmt.Errorf("status %d", err)
}

func (ev *event) resetCounters() {
	ev.num3xx = 0
	ev.num4xx = 0
	ev.num5xx = 0
}
