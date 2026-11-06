package fidohid

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/matejsmycka/linux-id/fidoauth"
	"github.com/psanford/uhid"
)

func New(ctx context.Context, name string) (*SoftToken, error) {
	d, err := uhid.NewDevice(name, rdesc)
	if err != nil {
		return nil, err
	}

	d.Data.Bus = busUSB
	d.Data.VendorID = vendorID
	d.Data.ProductID = productID
	d.SetUniq("linux-id")

	evtChan, err := d.Open(ctx)
	if err != nil {
		return nil, err
	}

	t := SoftToken{
		device:    d,
		evtChan:   evtChan,
		authEvent: make(chan AuthEvent, 1),

		msgTimeout:        defaultMsgTimeout,
		keepaliveInterval: defaultKeepaliveInterval,
	}

	return &t, nil
}

// SoftToken implements the CTAPHID transport (CTAP 2.1 §11.2) on top of a
// uhid device. At most one CTAP request is in flight at a time; requests on
// other channels are answered with ERR_CHANNEL_BUSY until it completes.
type SoftToken struct {
	device    eventWriter
	evtChan   chan uhid.Event
	authEvent chan AuthEvent

	// msgTimeout bounds the wait for a message's continuation packets.
	msgTimeout time.Duration
	// keepaliveInterval is how often CTAPHID_KEEPALIVE is sent while a
	// CTAPHID_CBOR request is pending.
	keepaliveInterval time.Duration

	// writeMu keeps the frames of one message contiguous on the wire.
	writeMu sync.Mutex

	mu      sync.Mutex
	lastCID uint32       // highest channel id handed out by CTAPHID_INIT
	busy    *transaction // the request being processed, if any
}

// eventWriter is the part of *uhid.Device the transport writes reports to.
type eventWriter interface {
	WriteEvent(interface{}) error
}

// transaction is the state of one in-flight CTAPHID_MSG or CTAPHID_CBOR request.
type transaction struct {
	chanID    uint32
	cmd       CmdType
	cancel    context.CancelFunc
	keepalive atomic.Uint32 // KeepaliveStatus sent while the request is pending

	// guarded by SoftToken.writeMu
	finished bool
}

// KeepaliveStatus is the status byte of a CTAPHID_KEEPALIVE message.
type KeepaliveStatus uint8

const (
	KeepaliveProcessing KeepaliveStatus = 1
	KeepaliveUPNeeded   KeepaliveStatus = 2
)

type AuthEvent struct {
	chanID uint32
	cmd    CmdType
	ctx    context.Context
	tx     *transaction

	Req     *fidoauth.AuthenticatorRequest
	RawCbor []byte // non-nil iff this is a CTAP2 (CmdCbor) event
	Error   error
}

// Context is cancelled when the host sends CTAPHID_CANCEL for this request or
// re-initialises its channel.
func (e AuthEvent) Context() context.Context {
	if e.ctx == nil {
		return context.Background()
	}
	return e.ctx
}

// SetKeepalive changes the status reported in the CTAPHID_KEEPALIVE messages
// sent while this request is pending. Handlers report KeepaliveUPNeeded while
// waiting for the user so the platform can prompt them.
func (e AuthEvent) SetKeepalive(s KeepaliveStatus) {
	if e.tx != nil {
		e.tx.keepalive.Store(uint32(s))
	}
}

func (t *SoftToken) Events() chan AuthEvent {
	return t.authEvent
}

// message is a fully reassembled CTAPHID request.
type message struct {
	chanID uint32
	cmd    CmdType
	data   []byte
}

// assembly is a request whose continuation packets are still arriving.
type assembly struct {
	message
	total   int
	nextSeq uint8
}

func (t *SoftToken) Run(ctx context.Context) {
	pktChan := make(chan Packet)
	go parsePackets(ctx, t.evtChan, pktChan)

	var (
		asm   *assembly
		timer = time.NewTimer(t.msgTimeout)
	)
	timer.Stop()

	for {
		var timeout <-chan time.Time
		if asm != nil {
			timeout = timer.C
		}

		var pkt Packet
		select {
		case pkt = <-pktChan:
		case <-timeout:
			log.Printf("ctaphid: message on channel %08x timed out", asm.chanID)
			t.writeError(asm.chanID, errMsgTimeout)
			asm = nil
			continue
		case <-ctx.Done():
			return
		}

		if !pkt.IsInitial {
			if asm == nil || pkt.ChannelID != asm.chanID {
				// Stray continuation packet: nothing to attach it to.
				continue
			}
			if pkt.SeqNo != asm.nextSeq {
				t.writeError(asm.chanID, errInvalidSeq)
				asm = nil
				continue
			}
			asm.nextSeq++
			asm.data = append(asm.data, pkt.Data[:min(len(pkt.Data), asm.total-len(asm.data))]...)
		} else {
			if pkt.ChannelID == 0 || (pkt.ChannelID != broadcastCID && !t.validChannel(pkt.ChannelID)) {
				t.writeError(pkt.ChannelID, errInvalidChannel)
				continue
			}
			if pkt.ChannelID == broadcastCID && pkt.Command != CmdInit {
				t.writeError(pkt.ChannelID, errInvalidChannel)
				continue
			}
			if asm != nil {
				switch {
				case pkt.ChannelID == asm.chanID && pkt.Command == CmdInit:
					// Resync: the host abandons the partial message.
					asm = nil
				case pkt.ChannelID == asm.chanID:
					t.writeError(asm.chanID, errInvalidSeq)
					asm = nil
					continue
				case pkt.Command != CmdInit:
					t.writeError(pkt.ChannelID, errChannelBusy)
					continue
				}
			}
			if int(pkt.TotalSize) > maxMessageSize {
				t.writeError(pkt.ChannelID, errInvalidLen)
				continue
			}
			total := int(pkt.TotalSize)
			a := &assembly{
				message: message{chanID: pkt.ChannelID, cmd: pkt.Command},
				total:   total,
			}
			a.data = append(make([]byte, 0, total), pkt.Data[:min(len(pkt.Data), total)]...)
			if len(a.data) < total {
				// A broadcast INIT never needs continuation packets; only
				// track real multi-packet requests.
				asm = a
				timer.Reset(t.msgTimeout)
				continue
			}
			t.dispatch(ctx, a.message)
			continue
		}

		if len(asm.data) >= asm.total {
			timer.Stop()
			msg := asm.message
			asm = nil
			t.dispatch(ctx, msg)
		}
	}
}

func (t *SoftToken) validChannel(cid uint32) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return cid <= t.lastCID
}

func (t *SoftToken) allocateChannel() uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastCID++
	if t.lastCID == broadcastCID {
		t.lastCID = 1
	}
	return t.lastCID
}

func (t *SoftToken) dispatch(ctx context.Context, msg message) {
	switch msg.cmd {
	case CmdInit:
		if len(msg.data) != 8 {
			t.writeError(msg.chanID, errInvalidLen)
			return
		}
		var nonce [8]byte
		copy(nonce[:], msg.data)

		chanID := msg.chanID
		if chanID == broadcastCID {
			chanID = t.allocateChannel()
		} else {
			// INIT on an allocated channel resyncs it, aborting any
			// request still in flight there.
			t.abort(chanID)
		}
		resp := newInitResponse(chanID, nonce)
		t.writeMu.Lock()
		err := writeFrames(t.device, msg.chanID, CmdInit, resp.Marshal())
		t.writeMu.Unlock()
		if err != nil {
			log.Printf("Write Init resp err: %s", err)
		}
	case CmdPing:
		t.writeMu.Lock()
		err := writeFrames(t.device, msg.chanID, CmdPing, msg.data)
		t.writeMu.Unlock()
		if err != nil {
			log.Printf("Write Ping resp err: %s", err)
		}
	case CmdWink:
		t.writeMu.Lock()
		err := writeFrames(t.device, msg.chanID, CmdWink, nil)
		t.writeMu.Unlock()
		if err != nil {
			log.Printf("Write Wink resp err: %s", err)
		}
	case CmdCancel:
		// CANCEL has no response of its own: the cancelled request is
		// answered with CTAP2_ERR_KEEPALIVE_CANCEL by its handler.
		t.mu.Lock()
		if t.busy != nil && t.busy.chanID == msg.chanID {
			log.Printf("ctaphid: cancel on channel %08x", msg.chanID)
			t.busy.cancel()
		}
		t.mu.Unlock()
	case CmdMsg, CmdCbor:
		t.startRequest(ctx, msg)
	default:
		log.Printf("unsupported cmd: %s", msg.cmd)
		t.writeError(msg.chanID, errInvalidCmd)
	}
}

func (t *SoftToken) startRequest(ctx context.Context, msg message) {
	t.mu.Lock()
	if t.busy != nil {
		t.mu.Unlock()
		t.writeError(msg.chanID, errChannelBusy)
		return
	}
	reqCtx, cancel := context.WithCancel(ctx)
	tx := &transaction{chanID: msg.chanID, cmd: msg.cmd, cancel: cancel}
	tx.keepalive.Store(uint32(KeepaliveProcessing))
	t.busy = tx
	t.mu.Unlock()

	evt := AuthEvent{chanID: msg.chanID, cmd: msg.cmd, ctx: reqCtx, tx: tx}
	if msg.cmd == CmdCbor {
		evt.RawCbor = msg.data
		if evt.RawCbor == nil {
			evt.RawCbor = []byte{}
		}
		go t.sendKeepalives(tx)
	} else {
		evt.Req, evt.Error = fidoauth.DecodeAuthenticatorRequest(msg.data)
	}

	select {
	case t.authEvent <- evt:
	case <-ctx.Done():
	}
}

// abort cancels the in-flight request on chanID and drops its response.
func (t *SoftToken) abort(chanID uint32) {
	t.mu.Lock()
	tx := t.busy
	if tx == nil || tx.chanID != chanID {
		t.mu.Unlock()
		return
	}
	t.busy = nil
	t.mu.Unlock()

	tx.cancel()
	t.writeMu.Lock()
	tx.finished = true
	t.writeMu.Unlock()
}

func (t *SoftToken) sendKeepalives(tx *transaction) {
	ticker := time.NewTicker(t.keepaliveInterval)
	defer ticker.Stop()
	for range ticker.C {
		t.writeMu.Lock()
		if tx.finished {
			t.writeMu.Unlock()
			return
		}
		err := writeFrames(t.device, tx.chanID, CmdKeepalive, []byte{byte(tx.keepalive.Load())})
		t.writeMu.Unlock()
		if err != nil {
			log.Printf("Write Keepalive err: %s", err)
		}
	}
}

// respond writes the response to evt's request and frees the transport for
// the next one. A response to a request that was already answered or aborted
// is dropped.
func (t *SoftToken) respond(evt AuthEvent, cmd CmdType, payload []byte) error {
	t.writeMu.Lock()
	if evt.tx != nil {
		if evt.tx.finished {
			t.writeMu.Unlock()
			return nil
		}
		evt.tx.finished = true
	}
	err := writeFrames(t.device, evt.chanID, cmd, payload)
	t.writeMu.Unlock()

	if evt.tx != nil {
		evt.tx.cancel()
		t.mu.Lock()
		if t.busy == evt.tx {
			t.busy = nil
		}
		t.mu.Unlock()
	}
	return err
}

// Complete must be called once the handler for evt has returned. If the
// handler did not write a response, the host gets ERR_OTHER instead of
// waiting forever, and the transport is freed for the next request.
func (t *SoftToken) Complete(evt AuthEvent) {
	if evt.tx == nil {
		return
	}
	t.writeMu.Lock()
	finished := evt.tx.finished
	t.writeMu.Unlock()
	if !finished {
		log.Printf("ctaphid: handler for %s returned without a response", evt.cmd)
		t.respond(evt, CmdError, []byte{errOther})
	}
}

func (t *SoftToken) writeError(chanID uint32, code byte) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if err := writeFrames(t.device, chanID, CmdError, []byte{code}); err != nil {
		log.Printf("Write error resp err: %s", err)
	}
}

const (
	busUSB = 0x03

	vendorID  = 0x15d9
	productID = 0x0a37

	frameTypeInit = 0x80
	frameTypeCont = 0x00

	CmdPing      CmdType = 0x01 // Echo data through local processor only
	CmdMsg       CmdType = 0x03 // Send U2F message frame
	CmdLock      CmdType = 0x04 // Send lock channel command
	CmdInit      CmdType = 0x06 // Channel initialization
	CmdWink      CmdType = 0x08 // Send device identification wink
	CmdCbor      CmdType = 0x10 // Send encapsulated CTAP CBOR
	CmdCancel    CmdType = 0x11 // Cancel any outstanding request on this channel
	CmdKeepalive CmdType = 0x3b // Sent while processing a request
	CmdSync      CmdType = 0x3c // Protocol resync command
	CmdError     CmdType = 0x3f // Error response

	broadcastCID = 0xffffffff

	// CTAPHID_ERROR codes (CTAP 2.1 §11.2.9.1.6).
	errInvalidCmd     = 0x01
	errInvalidLen     = 0x03
	errInvalidSeq     = 0x04
	errMsgTimeout     = 0x05
	errChannelBusy    = 0x06
	errInvalidChannel = 0x0b
	errOther          = 0x7f

	vendorSpecificFirstCmd = 0x40
	vendorSpecificLastCmd  = 0x7f

	reportLen            = 64
	initialPacketDataLen = reportLen - 7
	contPacketDataLen    = reportLen - 5
	maxMessageSize       = initialPacketDataLen + 128*contPacketDataLen

	u2fProtocolVersion = 2
	deviceMajor        = 1
	deviceMinor        = 0
	deviceBuild        = 0
	winkCapability     = 0x01
	lockCapability     = 0x02
	cborCapability     = 0x04
	nmsgCapability     = 0x08
)

const (
	defaultMsgTimeout        = 3 * time.Second
	defaultKeepaliveInterval = 100 * time.Millisecond
)

type CmdType uint8

func (c CmdType) IsVendorSpecific() bool {
	return c >= vendorSpecificFirstCmd && c <= vendorSpecificLastCmd
}

func (c CmdType) String() string {
	switch c {
	case CmdPing:
		return "CmdPing"
	case CmdMsg:
		return "CmdMsg"
	case CmdLock:
		return "CmdLock"
	case CmdInit:
		return "CmdInit"
	case CmdWink:
		return "CmdWink"
	case CmdSync:
		return "CmdSync"
	case CmdError:
		return "CmdError"
	case CmdCbor:
		return "CmdCbor"
	case CmdCancel:
		return "CmdCancel"
	case CmdKeepalive:
		return "CmdKeepalive"
	}

	if c >= vendorSpecificFirstCmd && c <= vendorSpecificLastCmd {
		return fmt.Sprintf("CmdVendor<%d>", c)
	}
	return fmt.Sprintf("CmdUnknown<%d>", c)
}

// src: http://www.usb.org/developers/hidpage/HUTRR48.pdf
var rdesc = []byte{
	0x06, 0xd0, 0xf1, //	USAGE_PAGE (FIDO Alliance)
	0x09, 0x01, //				USAGE (U2F HID Authenticator Device)
	0xa1, 0x01, //				COLLECTION (Application)
	0x09, 0x20, //					USAGE (Input Report Data)
	0x15, 0x00, //					LOGICAL_MINIMUM (0)
	0x26, 0xff, 0x00, //		LOGICAL_MAXIMUM (255)
	0x75, 0x08, //					REPORT_SIZE (8)
	0x95, 0x40, //					REPORT_COUNT (64)
	0x81, 0x02, //					INPUT (Data,Var,Abs)
	0x09, 0x21, //					USAGE (Output Report Data)
	0x15, 0x00, //					LOGICAL_MINIMUM (0)
	0x26, 0xff, 0x00, //		LOGICAL_MAXIMUM (255)
	0x75, 0x08, //					REPORT_SIZE (8)
	0x95, 0x40, //					REPORT_COUNT (64)
	0x91, 0x02, //					OUTPUT (Data,Var,Abs)
	0xc0, //							END_COLLECTION
}

func parsePackets(ctx context.Context, evtChan chan uhid.Event, pktChan chan Packet) {
	for {
		var (
			evt uhid.Event
			ok  bool
		)

		select {
		case evt, ok = <-evtChan:
			if !ok {
				return
			}
		case <-ctx.Done():
			return
		}

		if evt.Err != nil {
			log.Fatalf("got evt err: %s", evt.Err)
		}

		// Output means the kernel has sent us data
		if evt.Type == uhid.Output {

			r := newPacketReader(bytes.NewReader(evt.Data))
			b1 := make([]byte, 1)
			r.ReadFull(b1) // ignore first byte

			var channelID uint32
			r.Read(binary.BigEndian, &channelID)

			_, err := r.ReadFull(b1)
			if err != nil {
				log.Printf("U2F protocol read error")
				continue
			}
			typeOrSeqNo := b1[0]

			if typeOrSeqNo&frameTypeInit == frameTypeInit {
				typ := typeOrSeqNo
				cmd := typ ^ frameTypeInit

				var totalSize uint16
				r.Read(binary.BigEndian, &totalSize)

				data := make([]byte, initialPacketDataLen)
				_, err := r.ReadFull(data)
				if err != nil {
					log.Printf("U2F protocol read error")
					continue
				}

				p := Packet{
					ChannelID: channelID,
					IsInitial: true,
					Command:   CmdType(cmd),
					TotalSize: totalSize,
					Data:      data,
				}

				select {
				case pktChan <- p:
				case <-ctx.Done():
					return
				}
			} else {
				seqNo := typeOrSeqNo

				data := make([]byte, contPacketDataLen)
				_, err := r.ReadFull(data)
				if err != nil {
					log.Printf("U2F protocol read error")
					continue
				}

				p := Packet{
					ChannelID: channelID,
					SeqNo:     seqNo,
					Data:      data,
				}

				select {
				case pktChan <- p:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

type Packet struct {
	ChannelID uint32
	IsInitial bool
	Command   CmdType
	SeqNo     byte
	TotalSize uint16
	Data      []byte
}

func newPacketReader(r io.Reader) *packetReader {
	return &packetReader{
		r: r,
	}
}

type packetReader struct {
	r   io.Reader
	err error
}

func (pr *packetReader) Read(order binary.ByteOrder, data interface{}) error {
	if pr.err != nil {
		return pr.err
	}

	err := binary.Read(pr.r, order, data)
	if err != nil {
		pr.err = err
	}
	return err
}

func (pr *packetReader) ReadFull(b []byte) (int, error) {
	if pr.err != nil {
		return 0, pr.err
	}

	n, err := io.ReadFull(pr.r, b)
	if err != nil {
		pr.err = err
		return n, err
	}
	return n, nil
}

type frameInit struct {
	ChannelID       uint32
	Command         uint8
	Data            []byte
	TotalPayloadLen uint16
}

func (fi *frameInit) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, fi.ChannelID)
	buf.WriteByte(fi.Command)
	binary.Write(buf, binary.BigEndian, fi.TotalPayloadLen)
	buf.Write(fi.Data)
	if len(fi.Data) < initialPacketDataLen {
		pad := make([]byte, initialPacketDataLen-len(fi.Data))
		buf.Write(pad)
	}

	return buf.Bytes()
}

type frameCont struct {
	ChannelID uint32
	SeqNo     uint8
	Data      []byte
}

func (fi *frameCont) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, fi.ChannelID)
	buf.WriteByte(fi.SeqNo)
	buf.Write(fi.Data)
	if len(fi.Data) < contPacketDataLen {
		pad := make([]byte, contPacketDataLen-len(fi.Data))

		buf.Write(pad)
	}
	return buf.Bytes()
}

type initResponse struct {
	Nonce              [8]byte
	Channel            uint32
	ProtocolVersion    byte
	MajorDeviceVersion byte
	MinorDeviceVersion byte
	BuildDeviceVersion byte
	RawCapabilities    byte
}

func newInitResponse(channelID uint32, nonce [8]byte) *initResponse {
	return &initResponse{
		Nonce:              nonce,
		Channel:            channelID,
		ProtocolVersion:    u2fProtocolVersion,
		MajorDeviceVersion: deviceMajor,
		MinorDeviceVersion: deviceMinor,
		BuildDeviceVersion: deviceBuild,
		RawCapabilities:    winkCapability | cborCapability,
	}
}

func (resp *initResponse) Marshal() []byte {
	buf := new(bytes.Buffer)
	buf.Write(resp.Nonce[:])
	binary.Write(buf, binary.BigEndian, resp.Channel)
	buf.Write([]byte{
		resp.ProtocolVersion,
		resp.MajorDeviceVersion,
		resp.MinorDeviceVersion,
		resp.BuildDeviceVersion,
		resp.RawCapabilities,
	})

	return buf.Bytes()
}

func (t *SoftToken) WriteResponse(ctx context.Context, evt AuthEvent, data []byte, status uint16) error {
	statusBytes := binary.BigEndian.AppendUint16(nil, status)
	return t.respond(evt, evt.cmd, append(append([]byte{}, data...), statusBytes...))
}

// WriteCtap2Response sends a CTAP2 response: [1-byte status] + [CBOR payload].
// No trailing U2F status word is appended.
func (t *SoftToken) WriteCtap2Response(ctx context.Context, evt AuthEvent, status byte, data []byte) error {
	payload := append([]byte{status}, data...)
	return t.respond(evt, CmdCbor, payload)
}

// writeFrames splits data into an initialisation packet and as many
// continuation packets as needed. The caller must hold SoftToken.writeMu.
func writeFrames(d eventWriter, chanID uint32, cmd CmdType, data []byte) error {
	totalSize := uint16(len(data))
	first := data[:min(len(data), initialPacketDataLen)]
	data = data[len(first):]

	frames := [][]byte{(&frameInit{
		ChannelID:       chanID,
		Command:         uint8(cmd) | frameTypeInit,
		Data:            first,
		TotalPayloadLen: totalSize,
	}).Marshal()}
	for seqNo := uint8(0); len(data) > 0; seqNo++ {
		chunk := data[:min(len(data), contPacketDataLen)]
		data = data[len(chunk):]
		frames = append(frames, (&frameCont{ChannelID: chanID, SeqNo: seqNo, Data: chunk}).Marshal())
	}

	for _, payload := range frames {
		resp := uhid.Input2Request{
			RequestType: uhid.Input2,
			DataSize:    uint16(len(payload)),
		}
		copy(resp.Data[:], payload)
		if err := d.WriteEvent(resp); err != nil {
			return err
		}
	}
	return nil
}
