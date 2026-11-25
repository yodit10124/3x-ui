package service

import (
	"io"
	"testing"
	"time"
)

// endlessReader returns an unbounded stream of 'x' bytes and counts
// how many were read. A reader that never returns io.EOF.
type endlessReader struct{ read int64 }

func (r *endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	r.read += int64(len(p))
	return len(p), nil
}

func (r *endlessReader) Close() error { return nil }

// TestDiscardTestBodyCapsRead (L-7): the outbound test only measures
// latency and discards the body, so it must stop after the cap even
// when the server streams forever.
func TestDiscardTestBodyCapsRead(t *testing.T) {
	body := &endlessReader{}
	done := make(chan struct{})
	go func() {
		discardTestBody(io.NopCloser(body))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("discardTestBody did not return within 5s on an endless body")
	}
	if body.read != maxOutboundTestBodyBytes {
		t.Fatalf("discardTestBody read %d bytes, want exactly the %d-byte cap", body.read, maxOutboundTestBodyBytes)
	}
}
