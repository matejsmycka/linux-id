// Package notify shows desktop notifications through the freedesktop
// notification service (org.freedesktop.Notifications) on the session bus.
//
// It is best-effort by design: when the session bus or a notification daemon
// is missing, Show returns an error and callers carry on without one.
package notify

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

// Message is the text of a notification.
type Message struct {
	Title string
	Body  string
	// Cancelable adds a "Cancel" action when the daemon supports actions.
	Cancelable bool
	// Expire is how long the daemon should show the notification before
	// withdrawing it on its own; zero leaves it to the daemon.
	Expire time.Duration
}

// Notifier shows notifications.
type Notifier interface {
	Show(Message) (Notification, error)
}

// Notification is a notification that is on screen.
type Notification interface {
	// Update replaces the notification's text in place.
	Update(Message)
	// Close withdraws the notification. Further calls do nothing.
	Close()
	// Cancelled is closed when the user picks the notification's Cancel
	// action.
	Cancelled() <-chan struct{}
}

const (
	busName       = "org.freedesktop.Notifications"
	objectPath    = dbus.ObjectPath("/org/freedesktop/Notifications")
	iface         = "org.freedesktop.Notifications"
	cancelAction  = "cancel"
	callTimeout   = 2 * time.Second
	urgencyNormal = byte(1)
)

// DBus is a Notifier backed by the session bus. It connects on first use and
// reconnects after the connection is lost. Safe for concurrent use.
type DBus struct {
	appName string
	icon    string

	mu     sync.Mutex
	conn   *dbus.Conn
	caps   map[string]bool
	active map[uint32]*dbusNotification
}

// NewDBus returns a Notifier that sends notifications as appName with the
// named icon (an icon theme name; may be empty).
func NewDBus(appName, icon string) *DBus {
	return &DBus{appName: appName, icon: icon, active: map[uint32]*dbusNotification{}}
}

// SessionBusAddress finds the session bus the way a service in a systemd
// user unit has to: DBUS_SESSION_BUS_ADDRESS from the user manager, else the
// standard socket in the runtime directory. Unlike dbus.SessionBus it never
// autolaunches a bus.
func SessionBusAddress(getenv func(string) string, uid int) string {
	if addr := getenv("DBUS_SESSION_BUS_ADDRESS"); addr != "" && addr != "autolaunch:" {
		return addr
	}
	dir := getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = fmt.Sprintf("/run/user/%d", uid)
	}
	return "unix:path=" + dbus.EscapeBusAddressValue(dir+"/bus")
}

// connLocked returns a live connection, connecting if needed. d.mu is held.
func (d *DBus) connLocked() (*dbus.Conn, error) {
	if d.conn != nil && d.conn.Connected() {
		return d.conn, nil
	}
	d.conn, d.caps = nil, nil

	addr := SessionBusAddress(os.Getenv, os.Getuid())
	conn, err := dbus.Connect(addr)
	if err != nil {
		return nil, fmt.Errorf("notify: connect to session bus %s: %w", addr, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	var caps []string
	if err := conn.Object(busName, objectPath).CallWithContext(ctx, iface+".GetCapabilities", 0).Store(&caps); err != nil {
		conn.Close()
		return nil, fmt.Errorf("notify: no notification service: %w", err)
	}
	if err := conn.AddMatchSignal(
		dbus.WithMatchSender(busName),
		dbus.WithMatchObjectPath(objectPath),
		dbus.WithMatchInterface(iface),
	); err != nil {
		conn.Close()
		return nil, fmt.Errorf("notify: subscribe to signals: %w", err)
	}
	sigCh := make(chan *dbus.Signal, 16)
	conn.Signal(sigCh)
	go d.dispatch(sigCh)

	d.conn = conn
	d.caps = map[string]bool{}
	for _, c := range caps {
		d.caps[c] = true
	}
	if !d.caps["actions"] {
		log.Print("notify: notification daemon does not support actions; no Cancel button")
	}
	return conn, nil
}

// dispatch routes ActionInvoked and NotificationClosed to the notification
// they are for. It returns when the connection closes its signal channel.
func (d *DBus) dispatch(sigCh <-chan *dbus.Signal) {
	for sig := range sigCh {
		if len(sig.Body) < 2 {
			continue
		}
		id, ok := sig.Body[0].(uint32)
		if !ok {
			continue
		}
		d.mu.Lock()
		n := d.active[id]
		d.mu.Unlock()
		// Only the daemon that showed the notification speaks for it: any
		// session bus client can send a signal addressed to us.
		if n == nil || sig.Sender != n.owner {
			continue
		}
		switch sig.Name {
		case iface + ".ActionInvoked":
			if key, _ := sig.Body[1].(string); key == cancelAction {
				n.cancelOnce.Do(func() { close(n.cancelled) })
			}
		case iface + ".NotificationClosed":
			// Dismissed or expired. The request goes on; an Update would show
			// it again.
		}
	}
}

// Show displays msg.
func (d *DBus) Show(msg Message) (Notification, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	conn, err := d.connLocked()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	var owner string
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, busName).Store(&owner); err != nil {
		d.dropLocked(conn, err)
		return nil, fmt.Errorf("notify: no notification service: %w", err)
	}
	var id uint32
	call := conn.Object(busName, objectPath).CallWithContext(ctx, iface+".Notify", 0, d.notifyArgs(0, msg)...)
	if err := call.Store(&id); err != nil {
		d.dropLocked(conn, err)
		return nil, fmt.Errorf("notify: Notify: %w", err)
	}
	n := &dbusNotification{d: d, conn: conn, id: id, owner: owner, cancelled: make(chan struct{})}
	d.active[id] = n
	return n, nil
}

// dropLocked closes conn after err if the connection is no longer usable, so
// the next Show reconnects. d.mu is held.
func (d *DBus) dropLocked(conn *dbus.Conn, err error) {
	if errors.Is(err, context.DeadlineExceeded) || !conn.Connected() {
		conn.Close()
		d.conn = nil
	}
}

// notifyArgs builds the arguments of a Notify call. d.mu is held.
func (d *DBus) notifyArgs(replacesID uint32, msg Message) []any {
	body := msg.Body
	if d.caps["body-markup"] {
		body = escapeMarkup(body)
	}
	actions := []string{}
	if msg.Cancelable && d.caps["actions"] {
		actions = []string{cancelAction, "Cancel"}
	}
	hints := map[string]dbus.Variant{
		// Normal urgency: critical would bypass do-not-disturb on some
		// daemons but is styled as an alarm, and this is a prompt the user
		// asked for a moment ago.
		"urgency": dbus.MakeVariant(urgencyNormal),
		// Do not keep a prompt that is no longer pending in the history.
		"transient": dbus.MakeVariant(true),
	}
	expire := int32(-1)
	if msg.Expire > 0 {
		expire = int32(msg.Expire / time.Millisecond)
	}
	return []any{d.appName, replacesID, d.icon, msg.Title, body, actions, hints, expire}
}

var markupEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// escapeMarkup escapes text for daemons that parse the body as markup.
func escapeMarkup(s string) string { return markupEscaper.Replace(s) }

type dbusNotification struct {
	d          *DBus
	conn       *dbus.Conn
	id         uint32
	owner      string // unique bus name of the daemon that showed it
	closed     bool   // guarded by d.mu
	cancelled  chan struct{}
	cancelOnce sync.Once
}

func (n *dbusNotification) Cancelled() <-chan struct{} { return n.cancelled }

// Update and Close do not wait for the daemon's reply, so they never hold up
// the request that the notification is about.

func (n *dbusNotification) Update(msg Message) {
	n.d.mu.Lock()
	defer n.d.mu.Unlock()
	if n.closed {
		return
	}
	n.conn.Object(busName, objectPath).Go(iface+".Notify", dbus.FlagNoReplyExpected, nil, n.d.notifyArgs(n.id, msg)...)
}

func (n *dbusNotification) Close() {
	n.d.mu.Lock()
	defer n.d.mu.Unlock()
	if n.closed {
		return
	}
	n.closed = true
	delete(n.d.active, n.id)
	n.conn.Object(busName, objectPath).Go(iface+".CloseNotification", dbus.FlagNoReplyExpected, nil, n.id)
}
