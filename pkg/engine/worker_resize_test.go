package engine

import (
	"reflect"
	"sort"
	"testing"
	"time"
)

func TestSetWorkerCountStopsHighestWorkerIDs(t *testing.T) {
	eng := NewEngine(10, 100, 0.01)
	eng.Start()
	defer eng.Shutdown()

	deadline := time.Now().Add(time.Second)
	for eng.activeWorkers.Load() != 10 {
		if time.Now().After(deadline) {
			t.Fatalf("active workers = %d, want 10 before resize", eng.activeWorkers.Load())
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(25 * time.Millisecond)

	eng.SetWorkerCount(5)

	var stoppedIDs []int
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for len(stoppedIDs) < 5 {
		select {
		case event := <-eng.LogEvents:
			if event.Type != EventWorkerStopped {
				continue
			}
			workerID, ok := event.Metadata["worker_id"].(int)
			if !ok {
				t.Fatalf("worker stop event has invalid worker_id: %#v", event.Metadata["worker_id"])
			}
			stoppedIDs = append(stoppedIDs, workerID)
		case <-timer.C:
			t.Fatalf("timed out waiting for resized workers to stop; got IDs %v", stoppedIDs)
		}
	}

	sort.Ints(stoppedIDs)
	want := []int{5, 6, 7, 8, 9}
	if !reflect.DeepEqual(stoppedIDs, want) {
		t.Fatalf("stopped worker IDs = %v, want highest IDs %v", stoppedIDs, want)
	}
	deadline = time.Now().Add(time.Second)
	for eng.activeWorkers.Load() != 5 {
		if time.Now().After(deadline) {
			t.Fatalf("active workers after resize = %d, want 5", eng.activeWorkers.Load())
		}
		time.Sleep(time.Millisecond)
	}
}
