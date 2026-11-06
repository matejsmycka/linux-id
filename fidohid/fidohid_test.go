package fidohid

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/psanford/uhid"
)

// fakeDevice records the input reports the transport writes and lets tests
// reassemble them into CTAPHID responses.
type fakeDevice struct {
	mu      sync.Mutex
	reports [][]byte
	notify  chan struct{}
}

func (d *fakeDevice) WriteEvent(i interface{}) error {
	req := i.(uhid.Input2Request)
	d.mu.Lock()
	d.reports = append(d.reports, append([]byte{}, req.Data[:req.DataSize]...))
	d.mu.Unlock()
	select {
	case d.notify <- struct{}{}:
	default:
	}
	return nil
}

type response struct {
	cid  uint32
	cmd  CmdType
	data []byte
}

// next waits for the next complete response, skipping keepalives unless
// keepalives is set.
func (d *fakeDevice) next(t *testing.T, keepalives bool) response {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		d.mu.Lock()
		for len(d.reports) > 0 {
			r, ok := d.parse()
			if !ok {
				break
			}
			if r.cmd == CmdKeepalive && !keepalives {
				continue
			}
			d.mu.Unlock()
			return r
		}
		d.mu.Unlock()
		select {
		case <-d.notify:
		case <-time.After(10 * time.Millisecond):
		case <-deadline:
			t.Fatal("timed out waiting for a response")
		}
	}
}

// parse removes one complete message from d.reports. Caller holds d.mu.
func (d *fakeDevice) parse() (response, bool) {
	first := d.reports[0]
	cid := binary.BigEndian.Uint32(first[0:4])
	cmd := CmdType(first[4] &^ frameTypeInit)
	total := int(binary.BigEndian.Uint16(first[5:7]))
	data := append([]byte{}, first[7:7+min(total, initialPacketDataLen)]...)
	n := 1
	for len(data) < total {
		if n >= len(d.reports) {
			return response{}, false
		}
		cont := d.reports[n]
		data = append(data, cont[5:5+min(total-len(data), contPacketDataLen)]...)
		n++
	}
	d.reports = d.reports[n:]
	return response{cid: cid, cmd: cmd, data: data}, true
}

type harness struct {
	t      *testing.T
	token  *SoftToken
	dev    *fakeDevice
	events chan uhid.Event
}

func newHarness(t *testing.T, opts ...func(*SoftToken)) *harness {
	t.Helper()
	dev := &fakeDevice{notify: make(chan struct{}, 1)}
	events := make(chan uhid.Event)
	token := &SoftToken{
		device:            dev,
		evtChan:           events,
		authEvent:         make(chan AuthEvent, 1),
		msgTimeout:        defaultMsgTimeout,
		keepaliveInterval: defaultKeepaliveInterval,
	}
	for _, opt := range opts {
		opt(token)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go token.Run(ctx)
	return &harness{t: t, token: token, dev: dev, events: events}
}

// send writes msg to the transport as an init packet plus continuations.
func (h *harness) send(cid uint32, cmd CmdType, msg []byte) {
	h.sendRaw(cid, cmd, uint16(len(msg)), msg)
}

func (h *harness) sendRaw(cid uint32, cmd CmdType, total uint16, msg []byte) {
	h.t.Helper()
	first := msg[:min(len(msg), initialPacketDataLen)]
	rest := msg[len(first):]
	h.report((&frameInit{ChannelID: cid, Command: uint8(cmd) | frameTypeInit, Data: first, TotalPayloadLen: total}).Marshal())
	for seq := uint8(0); len(rest) > 0; seq++ {
		chunk := rest[:min(len(rest), contPacketDataLen)]
		rest = rest[len(chunk):]
		h.report((&frameCont{ChannelID: cid, SeqNo: seq, Data: chunk}).Marshal())
	}
}

func (h *harness) report(frame []byte) {
	// The kernel prefixes output reports with the report ID.
	h.events <- uhid.Event{Type: uhid.Output, Data: append([]byte{0}, frame...)}
}

func (h *harness) init() uint32 {
	h.t.Helper()
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	h.send(broadcastCID, CmdInit, nonce)
	r := h.dev.next(h.t, false)
	if r.cid != broadcastCID || r.cmd != CmdInit || !bytes.Equal(r.data[:8], nonce) {
		h.t.Fatalf("bad INIT response: %+v", r)
	}
	return binary.BigEndian.Uint32(r.data[8:12])
}

func (h *harness) expectError(cid uint32, code byte) {
	h.t.Helper()
	r := h.dev.next(h.t, false)
	if r.cmd != CmdError || r.cid != cid || len(r.data) != 1 || r.data[0] != code {
		h.t.Fatalf("got %+v, want ERROR 0x%02x on %08x", r, code, cid)
	}
}

func (h *harness) event() AuthEvent {
	h.t.Helper()
	select {
	case evt := <-h.token.Events():
		return evt
	case <-time.After(2 * time.Second):
		h.t.Fatal("no event dispatched")
		return AuthEvent{}
	}
}

func TestInitAllocatesDistinctChannels(t *testing.T) {
	h := newHarness(t)
	a, b := h.init(), h.init()
	if a == 0 || a == broadcastCID || a == b {
		t.Fatalf("bad channel ids %08x %08x", a, b)
	}
}

func TestInitCapabilitiesAdvertiseWinkAndCbor(t *testing.T) {
	h := newHarness(t)
	h.send(broadcastCID, CmdInit, make([]byte, 8))
	r := h.dev.next(t, false)
	if caps := r.data[16]; caps != winkCapability|cborCapability {
		t.Fatalf("capabilities = %#x", caps)
	}
}

func TestPingEchoesMultiPacketPayload(t *testing.T) {
	h := newHarness(t)
	cid := h.init()
	msg := bytes.Repeat([]byte("ping!"), 60) // 300 bytes: init + 5 continuations
	h.send(cid, CmdPing, msg)
	r := h.dev.next(t, false)
	if r.cid != cid || r.cmd != CmdPing || !bytes.Equal(r.data, msg) {
		t.Fatalf("ping echo mismatch: got %d bytes", len(r.data))
	}
}

func TestEmptyPingStillGetsAResponse(t *testing.T) {
	h := newHarness(t)
	cid := h.init()
	h.send(cid, CmdPing, nil)
	if r := h.dev.next(t, false); r.cmd != CmdPing || len(r.data) != 0 {
		t.Fatalf("got %+v", r)
	}
}

func TestWink(t *testing.T) {
	h := newHarness(t)
	cid := h.init()
	h.send(cid, CmdWink, nil)
	if r := h.dev.next(t, false); r.cmd != CmdWink || r.cid != cid {
		t.Fatalf("got %+v", r)
	}
}

func TestUnknownCommandIsInvalidCmd(t *testing.T) {
	h := newHarness(t)
	cid := h.init()
	h.send(cid, CmdLock, []byte{1})
	h.expectError(cid, errInvalidCmd)
}

func TestUnallocatedChannelRejected(t *testing.T) {
	h := newHarness(t)
	h.send(0x1234, CmdPing, []byte{1})
	h.expectError(0x1234, errInvalidChannel)
}

func TestBroadcastOnlyForInit(t *testing.T) {
	h := newHarness(t)
	h.send(broadcastCID, CmdPing, []byte{1})
	h.expectError(broadcastCID, errInvalidChannel)
}

func TestOversizedMessageRejected(t *testing.T) {
	h := newHarness(t)
	cid := h.init()
	h.sendRaw(cid, CmdCbor, maxMessageSize+1, []byte{4})
	h.expectError(cid, errInvalidLen)
}

func TestBadSequenceRejected(t *testing.T) {
	h := newHarness(t)
	cid := h.init()
	h.report((&frameInit{ChannelID: cid, Command: uint8(CmdPing) | frameTypeInit, Data: make([]byte, initialPacketDataLen), TotalPayloadLen: 100}).Marshal())
	h.report((&frameCont{ChannelID: cid, SeqNo: 1, Data: make([]byte, contPacketDataLen)}).Marshal())
	h.expectError(cid, errInvalidSeq)
}

func TestPartialMessageTimesOut(t *testing.T) {
	h := newHarness(t, func(st *SoftToken) { st.msgTimeout = 50 * time.Millisecond })
	cid := h.init()
	h.report((&frameInit{ChannelID: cid, Command: uint8(CmdPing) | frameTypeInit, Data: make([]byte, initialPacketDataLen), TotalPayloadLen: 100}).Marshal())
	h.expectError(cid, errMsgTimeout)
}

func TestOtherChannelBusyDuringAssembly(t *testing.T) {
	h := newHarness(t)
	a, b := h.init(), h.init()
	h.report((&frameInit{ChannelID: a, Command: uint8(CmdPing) | frameTypeInit, Data: make([]byte, initialPacketDataLen), TotalPayloadLen: 100}).Marshal())
	h.send(b, CmdPing, []byte{1})
	h.expectError(b, errChannelBusy)
}

func TestCborRequestDispatchedAndAnswered(t *testing.T) {
	h := newHarness(t)
	cid := h.init()
	h.send(cid, CmdCbor, []byte{0x04})
	evt := h.event()
	if !bytes.Equal(evt.RawCbor, []byte{0x04}) {
		t.Fatalf("RawCbor = %x", evt.RawCbor)
	}
	if err := h.token.WriteCtap2Response(context.Background(), evt, 0x00, []byte{0xa0}); err != nil {
		t.Fatal(err)
	}
	h.token.Complete(evt)
	r := h.dev.next(t, false)
	if r.cmd != CmdCbor || !bytes.Equal(r.data, []byte{0x00, 0xa0}) {
		t.Fatalf("got %+v", r)
	}
}

func TestBusyWhileRequestInFlight(t *testing.T) {
	h := newHarness(t)
	a, b := h.init(), h.init()
	h.send(a, CmdCbor, []byte{0x02})
	evt := h.event()

	h.send(b, CmdCbor, []byte{0x04})
	h.expectError(b, errChannelBusy)

	h.token.WriteCtap2Response(context.Background(), evt, 0x2e, nil)
	if r := h.dev.next(t, false); r.cid != a || r.cmd != CmdCbor {
		t.Fatalf("got %+v", r)
	}

	// Once answered, the transport takes the next request.
	h.send(b, CmdCbor, []byte{0x04})
	h.event()
}

func TestKeepaliveReportsUPNeeded(t *testing.T) {
	h := newHarness(t, func(st *SoftToken) { st.keepaliveInterval = 5 * time.Millisecond })
	cid := h.init()
	h.send(cid, CmdCbor, []byte{0x02})
	evt := h.event()

	if r := h.dev.next(t, true); r.cmd != CmdKeepalive || r.data[0] != byte(KeepaliveProcessing) {
		t.Fatalf("got %+v, want PROCESSING keepalive", r)
	}
	evt.SetKeepalive(KeepaliveUPNeeded)
	for {
		r := h.dev.next(t, true)
		if r.cmd != CmdKeepalive {
			t.Fatalf("got %+v", r)
		}
		if r.data[0] == byte(KeepaliveUPNeeded) {
			break
		}
	}

	h.token.WriteCtap2Response(context.Background(), evt, 0x00, nil)
	// Nothing but the response may follow; in particular no keepalive after it.
	for {
		r := h.dev.next(t, true)
		if r.cmd == CmdCbor {
			break
		}
	}
	time.Sleep(20 * time.Millisecond)
	h.dev.mu.Lock()
	n := len(h.dev.reports)
	h.dev.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d reports written after the response", n)
	}
}

func TestCancelCancelsRequestContext(t *testing.T) {
	h := newHarness(t)
	cid := h.init()
	h.send(cid, CmdCbor, []byte{0x02})
	evt := h.event()

	h.send(cid, CmdCancel, nil)
	select {
	case <-evt.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("context not cancelled")
	}
}

func TestCancelFromOtherChannelIgnored(t *testing.T) {
	h := newHarness(t)
	a, b := h.init(), h.init()
	h.send(a, CmdCbor, []byte{0x02})
	evt := h.event()

	h.send(b, CmdCancel, nil)
	h.send(b, CmdPing, []byte{9}) // PING is answered, proving CANCEL was processed
	h.dev.next(t, false)
	if evt.Context().Err() != nil {
		t.Fatal("request cancelled from another channel")
	}
}

func TestReinitAbortsRequestAndDropsLateResponse(t *testing.T) {
	h := newHarness(t)
	cid := h.init()
	h.send(cid, CmdCbor, []byte{0x02})
	evt := h.event()

	h.send(cid, CmdInit, make([]byte, 8))
	if r := h.dev.next(t, false); r.cmd != CmdInit || binary.BigEndian.Uint32(r.data[8:12]) != cid {
		t.Fatalf("resync should keep the channel id, got %+v", r)
	}
	if evt.Context().Err() == nil {
		t.Fatal("request not cancelled by resync")
	}

	h.token.WriteCtap2Response(context.Background(), evt, 0x2d, nil)
	h.send(cid, CmdPing, []byte{7})
	if r := h.dev.next(t, false); r.cmd != CmdPing {
		t.Fatalf("late response leaked: %+v", r)
	}
}

func TestCompleteAnswersUnansweredRequest(t *testing.T) {
	h := newHarness(t)
	cid := h.init()
	h.send(cid, CmdCbor, []byte{0x02})
	evt := h.event()
	h.token.Complete(evt)
	h.expectError(cid, errOther)

	h.send(cid, CmdCbor, []byte{0x04})
	h.event()
}
