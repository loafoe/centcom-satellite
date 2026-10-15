package running_image_vulnerabilities

import (
	"context"
	"errors"
	"sort"
	"sync"
)

// workers is how many AWS calls run concurrently. The SDK's standard
// retryer absorbs occasional throttling.
const workers = 8

// scan holds one Execute call's state.
type scan struct {
	payload Payload
	region  string
	account string
	ecr     ecrAPI
	insp    inspectorAPI

	images    map[string]*runningImage
	platforms map[platformKey][]*runningImage
	status    map[platformKey]string
	groups    map[string]*groupAcc

	// mu guards everything below images (and the images' platforms /
	// assessed / matched fields) while workers run.
	mu      sync.Mutex
	report  Report
	stopped bool
}

// forEach runs fn(0..n-1) on up to workers goroutines and returns the first
// error; once one fails, remaining items are skipped.
func forEach(n int, fn func(i int) error) error {
	var (
		wg    sync.WaitGroup
		once  sync.Once
		first error
		next  = make(chan int)
		done  = make(chan struct{})
	)
	for w := 0; w < min(workers, n); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				if err := fn(i); err != nil {
					once.Do(func() { first = err; close(done) })
				}
			}
		}()
	}
feed:
	for i := 0; i < n; i++ {
		select {
		case next <- i:
		case <-done:
			break feed
		}
	}
	close(next)
	wg.Wait()
	return first
}

// spend is checked before every AWS call: once the budget is gone the scan
// stops and returns what it has.
func (s *scan) spend(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		s.mu.Lock()
		s.stop()
		s.mu.Unlock()
		return err
	}
	return nil
}

// budgetErr reports whether err came from the time budget running out (or
// the caller going away), marking the scan stopped if so.
func (s *scan) budgetErr(ctx context.Context, err error) bool {
	if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		s.mu.Lock()
		s.stop()
		s.mu.Unlock()
		return true
	}
	return false
}

// stop must be called with mu held.
func (s *scan) stop() {
	s.stopped = true
	s.report.Complete = false
	s.report.StopReason = "time_budget"
}

// countCall bumps one of the report's call counters.
func (s *scan) countCall(c *int) {
	s.mu.Lock()
	*c++
	s.mu.Unlock()
}

func sortStrings(v []string) { sort.Strings(v) }
