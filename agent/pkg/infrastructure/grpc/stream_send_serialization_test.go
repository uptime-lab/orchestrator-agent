package grpc

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	proto "agent/pkg/infrastructure/grpc/proto"
)

// concurrencyFakeStream embeds the client-stream interface (so it satisfies the
// type with only Send implemented) and flags any overlapping Send call.
type concurrencyFakeStream struct {
	proto.NodeCommunication_EstablishStreamClient
	inFlight int32
	races    int32
}

func (f *concurrencyFakeStream) Send(*proto.NodeToPlatform) error {
	if atomic.AddInt32(&f.inFlight, 1) != 1 {
		atomic.AddInt32(&f.races, 1)
	}
	time.Sleep(50 * time.Microsecond) // widen the window a real Send would have
	atomic.AddInt32(&f.inFlight, -1)
	return nil
}

// sendOn must serialize writes: grpc-go forbids concurrent SendMsg on one stream,
// and the agent has many goroutines that write. Run under -race too.
func TestSendOnSerializesConcurrentWrites(t *testing.T) {
	c := &PlatformClient{}
	fake := &concurrencyFakeStream{}

	const goroutines = 32
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = c.sendOn(fake, &proto.NodeToPlatform{})
			}
		}()
	}
	wg.Wait()

	if r := atomic.LoadInt32(&fake.races); r != 0 {
		t.Errorf("observed %d overlapping Send calls; sendOn did not serialize", r)
	}
}
