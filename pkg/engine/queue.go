package engine

import (
	"container/heap"
	"context"
	"errors"
	"sync"
)

var ErrQueueClosed = errors.New("queue closed")

// JobQueue defines the interface for the engine's work queue.
// This abstraction allows swapping between simple FIFO channels
// and priority-based heuristics tracking.
type JobQueue interface {
	// Push adds a new job to the queue.
	// Must block if the queue is full, and return context.Canceled if the context is cancelled.
	Push(ctx context.Context, job Job) error

	// Pop retrieves the next job from the queue.
	// Must block until a job is available or the queue is closed.
	// Returns a job, a boolean indicating if the queue is still open, and an error if context cancelled.
	Pop(ctx context.Context) (Job, bool, error)

	// Len returns the number of jobs currently in the queue.
	Len() int

	// Close signals that no more jobs will be added.
	Close()

	// Drain empties the queue and returns the number of jobs discarded.
	Drain() int
}

// ─── ChannelQueue ────────────────────────────────────────────────────────────

// ChannelQueue is a simple FIFO queue backed by a standard Go channel.
type ChannelQueue struct {
	ch chan Job
}

func NewChannelQueue(size int) *ChannelQueue {
	return &ChannelQueue{
		ch: make(chan Job, size),
	}
}

func (q *ChannelQueue) Push(ctx context.Context, job Job) error {
	select {
	case q.ch <- job:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (q *ChannelQueue) Pop(ctx context.Context) (Job, bool, error) {
	select {
	case job, ok := <-q.ch:
		return job, ok, nil
	case <-ctx.Done():
		return Job{}, false, ctx.Err()
	}
}

func (q *ChannelQueue) Len() int {
	return len(q.ch)
}

func (q *ChannelQueue) Close() {
	close(q.ch)
}

func (q *ChannelQueue) Drain() int {
	count := 0
	for {
		select {
		case <-q.ch:
			count++
		default:
			return count
		}
	}
}

// ─── PriorityQueue ───────────────────────────────────────────────────────────

// priorityHeap implements heap.Interface and holds Jobs.
type priorityHeap []Job

func (h priorityHeap) Len() int           { return len(h) }
func jobTypeScore(t JobType) int {
	switch t {
	case JobTypeValidation:
		return 40
	case JobTypeParamFuzz:
		return 30
	case JobTypeDiscovery:
		return 20
	case JobTypeFuzz, "":
		return 10
	}
	return 0
}

func (h priorityHeap) Less(i, j int) bool {
	scoreI := jobTypeScore(h[i].Type)
	scoreJ := jobTypeScore(h[j].Type)
	if scoreI != scoreJ {
		return scoreI > scoreJ
	}
	if h[i].PriorityScore != h[j].PriorityScore {
		return h[i].PriorityScore > h[j].PriorityScore
	}
	if !h[i].CreatedAt.IsZero() && !h[j].CreatedAt.IsZero() {
		return h[i].CreatedAt.Before(h[j].CreatedAt)
	}
	return h[i].RunID < h[j].RunID
}
func (h priorityHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *priorityHeap) Push(x interface{}) {
	*h = append(*h, x.(Job))
}

func (h *priorityHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

// PriorityJobQueue implements JobQueue using a container/heap.
// It uses channel-based signaling to provide context-aware, leak-free blocking.
type PriorityJobQueue struct {
	mu       sync.Mutex
	h        *priorityHeap
	closed   bool
	maxLen   int
	notEmpty chan struct{}
	notFull  chan struct{}
}

func NewPriorityQueue(maxLen int) *PriorityJobQueue {
	q := &PriorityJobQueue{
		h:        &priorityHeap{},
		maxLen:   maxLen,
		notEmpty: make(chan struct{}, 1),
		notFull:  make(chan struct{}, 1),
	}
	heap.Init(q.h)
	return q
}

// signalNotEmptyLocked wakes a consumer when queued work remains. The caller
// must hold q.mu.
func (q *PriorityJobQueue) signalNotEmptyLocked() {
	if q.closed || q.h.Len() == 0 {
		return
	}
	select {
	case q.notEmpty <- struct{}{}:
	default:
	}
}

// signalNotFullLocked wakes a producer when capacity remains. Re-signaling
// after a successful Push lets a single bulk-capacity notification (for
// example, from Drain) cascade to all producers that can now make progress.
// The caller must hold q.mu.
func (q *PriorityJobQueue) signalNotFullLocked() {
	if q.closed || q.maxLen == 0 || q.h.Len() >= q.maxLen {
		return
	}
	select {
	case q.notFull <- struct{}{}:
	default:
	}
}

func (q *PriorityJobQueue) Push(ctx context.Context, job Job) error {
	for {
		q.mu.Lock()
		if q.closed {
			q.mu.Unlock()
			return ErrQueueClosed
		}
		if q.maxLen == 0 || q.h.Len() < q.maxLen {
			heap.Push(q.h, job)
			q.signalNotEmptyLocked()
			q.signalNotFullLocked()
			q.mu.Unlock()
			return nil
		}
		q.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-q.notFull:
			// Space might be available, loop and try again
		}
	}
}

func (q *PriorityJobQueue) Pop(ctx context.Context) (Job, bool, error) {
	for {
		q.mu.Lock()
		if q.h.Len() > 0 {
			job := heap.Pop(q.h).(Job)
			q.signalNotEmptyLocked()
			q.signalNotFullLocked()
			q.mu.Unlock()
			return job, true, nil
		}
		if q.closed {
			q.mu.Unlock()
			return Job{}, false, nil
		}
		q.mu.Unlock()

		select {
		case <-ctx.Done():
			return Job{}, false, ctx.Err()
		case <-q.notEmpty:
			// Items might be available, loop and try again
		}
	}
}

func (q *PriorityJobQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.h.Len()
}

func (q *PriorityJobQueue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.closed {
		q.closed = true
		close(q.notEmpty)
		close(q.notFull)
	}
}

func (q *PriorityJobQueue) Drain() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	count := q.h.Len()
	*q.h = (*q.h)[:0]
	if count > 0 {
		q.signalNotFullLocked()
	}
	return count
}

