package engine

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestPriorityQueueWakesConsumersForQueuedBurst(t *testing.T) {
	const consumerCount = 8

	q := NewPriorityQueue(consumerCount)
	previousProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previousProcs)
	ctx, cancel := context.WithCancel(context.Background())
	results := make(chan error, consumerCount)
	ready := make(chan struct{}, consumerCount)
	var wg sync.WaitGroup
	for i := 0; i < consumerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready <- struct{}{}
			_, ok, err := q.Pop(ctx)
			if err == nil && !ok {
				err = fmt.Errorf("queue closed before delivering a job")
			}
			results <- err
		}()
	}
	for i := 0; i < consumerCount; i++ {
		<-ready
	}
	time.Sleep(50 * time.Millisecond)

	for i := 0; i < consumerCount; i++ {
		if err := q.Push(context.Background(), Job{Path: fmt.Sprintf("/job-%d", i)}); err != nil {
			cancel()
			wg.Wait()
			t.Fatalf("Push() failed: %v", err)
		}
	}

	completed := 0
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	for completed < consumerCount {
		select {
		case err := <-results:
			if err != nil {
				cancel()
				wg.Wait()
				t.Fatalf("Pop() failed: %v", err)
			}
			completed++
		case <-timer.C:
			cancel()
			wg.Wait()
			t.Fatalf("only %d of %d consumers woke for an already-queued burst", completed, consumerCount)
		}
	}
	cancel()
	wg.Wait()
}

func TestPriorityQueueDrainWakesBlockedProducers(t *testing.T) {
	const (
		queueCapacity = 8
		producerCount = 4
	)

	q := NewPriorityQueue(queueCapacity)
	for i := 0; i < queueCapacity; i++ {
		if err := q.Push(context.Background(), Job{Path: fmt.Sprintf("/initial-%d", i)}); err != nil {
			t.Fatalf("Push() failed: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	results := make(chan error, producerCount)
	ready := make(chan struct{}, producerCount)
	var wg sync.WaitGroup
	for i := 0; i < producerCount; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ready <- struct{}{}
			results <- q.Push(ctx, Job{Path: fmt.Sprintf("/blocked-%d", i)})
		}(i)
	}
	for i := 0; i < producerCount; i++ {
		<-ready
	}
	time.Sleep(50 * time.Millisecond)

	if drained := q.Drain(); drained != queueCapacity {
		cancel()
		wg.Wait()
		t.Fatalf("Drain() removed %d jobs, want %d", drained, queueCapacity)
	}

	completed := 0
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	for completed < producerCount {
		select {
		case err := <-results:
			if err != nil {
				cancel()
				wg.Wait()
				t.Fatalf("Push() failed after drain: %v", err)
			}
			completed++
		case <-timer.C:
			cancel()
			wg.Wait()
			t.Fatalf("only %d of %d blocked producers woke after draining available capacity", completed, producerCount)
		}
	}
	cancel()
	wg.Wait()
}
