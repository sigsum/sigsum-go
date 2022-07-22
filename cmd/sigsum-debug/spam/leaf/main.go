package leaf

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"git.sigsum.org/sigsum-go/pkg/log"
)

func Main(args []string, cfg Config) error {
	if err := cfg.parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Duration)
	s := newStatus()

	var wg sync.WaitGroup
	events := make(chan *event, 1024)
	defer close(events)
	for i := uint64(0); i < cfg.NumSubmitters; i++ {
		wg.Add(1)
		w := worker{Config: cfg, outCh: events}
		go func() {
			defer wg.Done()
			defer cancel()
			if err := w.submit(ctx); err != nil {
				log.Fatal("submitter died: %v", err)
			}
		}()
	}

	var checkChs []chan *event
	for i := uint64(0); i < cfg.NumCheckers; i++ {
		checkCh := make(chan *event, 1024)
		checkChs = append(checkChs, checkCh)
		defer close(checkCh)

		wg.Add(1)
		w := worker{Config: cfg, inCh: checkCh, outCh: events}
		go func() {
			defer wg.Done()
			defer cancel()
			if err := w.check(ctx); err != nil {
				log.Fatal("checker died: %v", err)
			}
		}()
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	defer close(sigs)

	ticker := time.NewTicker(cfg.Interval)
	defer wg.Wait()
	defer cancel()
	defer ticker.Stop()

	log.Info("Output format is: \n\n%s\n\n", s.format())
	nextChecker := 0
	for {
		select {
		case <-ctx.Done():
			log.Info("received done signal, closing...")
			return nil
		case ev := <-events:
			s.register(ev)
			if cfg.NumCheckers > 0 && !ev.got200 {
				select {
				case checkChs[nextChecker] <- ev:
				default:
					log.Fatal("check channel %d is full", nextChecker)
				}
				nextChecker = (int(nextChecker) + 1) % int(cfg.NumCheckers)
			}
		case <-ticker.C:
			s.rotate(os.Stdout)
		case <-sigs:
			log.Info("received shutdown signal, closing...")
			return nil
		}
	}
	return nil
}
