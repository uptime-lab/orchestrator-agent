package grpc

import (
	"io"
	"log/slog"
	"testing"
)

// The offline queue had no field for a command's structured
// outputs, so a terminal status queued during a stream blip was replayed as
// `success` with an empty result. A playbook doing read_file -> write_file then
// wrote an empty value and stayed GREEN — worse than a failure, because a
// failure is visible and this was not.

func testQueue() *MessageQueue {
	return NewMessageQueue(10, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// The headline: what goes into the queue must come out of it.
func TestAQueuedCommandStatusKeepsItsResult(t *testing.T) {
	q := testQueue()
	q.EnqueueCommandStatusWithResult("n", "a", "t", "cmd-1", "success", 100, "done",
		map[string]string{"content": "the file body", "exit_code": "0"})

	drained := q.Drain()
	if len(drained) != 1 || drained[0].CommandStatus == nil {
		t.Fatalf("expected one command status, got %+v", drained)
	}
	got := drained[0].CommandStatus.Result
	if got["content"] != "the file body" {
		t.Errorf("the outputs were lost on the way through the queue: %v", got)
	}
	if got["exit_code"] != "0" {
		t.Errorf("exit_code lost: %v", got)
	}
}

// The map is copied on enqueue, not aliased: it is built per command, and the
// enqueue and the flush can be minutes apart with nothing forbidding the caller
// from reusing it in between.
func TestTheQueuedResultIsNotAliasedToTheCallersMap(t *testing.T) {
	q := testQueue()
	live := map[string]string{"content": "original"}
	q.EnqueueCommandStatusWithResult("n", "a", "t", "cmd-1", "success", 100, "", live)

	live["content"] = "mutated after the enqueue"
	live["injected"] = "should not appear"

	drained := q.Drain()
	got := drained[0].CommandStatus.Result
	if got["content"] != "original" {
		t.Errorf("the queued result followed the caller's mutation: %v", got)
	}
	if _, ok := got["injected"]; ok {
		t.Errorf("a key added after the enqueue reached the queued message: %v", got)
	}
}

// A status with no outputs must not manufacture an empty map: the platform
// distinguishes "no result" from "an empty result" when settling a block.
func TestAStatusWithNoOutputsQueuesNoResult(t *testing.T) {
	q := testQueue()
	q.EnqueueCommandStatus("n", "a", "t", "cmd-1", "success", 100, "done")

	drained := q.Drain()
	if drained[0].CommandStatus.Result != nil {
		t.Errorf("expected no result map, got %v", drained[0].CommandStatus.Result)
	}
}

// The plain form must remain a thin wrapper rather than a second implementation
// — two enqueue paths drifting apart is the shape of the original bug.
func TestBothEnqueueFormsProduceTheSameShape(t *testing.T) {
	plain := testQueue()
	plain.EnqueueCommandStatus("n", "a", "t", "cmd-1", "failed", 0, "boom")
	withResult := testQueue()
	withResult.EnqueueCommandStatusWithResult("n", "a", "t", "cmd-1", "failed", 0, "boom", nil)

	a := plain.Drain()[0].CommandStatus
	b := withResult.Drain()[0].CommandStatus
	if a.CommandID != b.CommandID || a.Status != b.Status || a.Details != b.Details || a.Progress != b.Progress {
		t.Errorf("the two enqueue forms disagree:\n  plain: %+v\n  with:  %+v", a, b)
	}
}
