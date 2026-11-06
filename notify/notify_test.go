package notify

import (
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

func TestSessionBusAddress(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"from the user manager", map[string]string{"DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus", "XDG_RUNTIME_DIR": "/elsewhere"}, "unix:path=/run/user/1000/bus"},
		{"runtime dir", map[string]string{"XDG_RUNTIME_DIR": "/run/user/1000"}, "unix:path=/run/user/1000/bus"},
		{"autolaunch is ignored", map[string]string{"DBUS_SESSION_BUS_ADDRESS": "autolaunch:", "XDG_RUNTIME_DIR": "/run/user/1000"}, "unix:path=/run/user/1000/bus"},
		{"nothing set", nil, "unix:path=/run/user/1234/bus"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SessionBusAddress(func(k string) string { return tc.env[k] }, 1234)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNotifyArgs(t *testing.T) {
	msg := Message{Title: "Sign in to a.example", Body: "for <bob> & co", Cancelable: true, Expire: 30 * time.Second}

	d := NewDBus("linux-id", "icon")
	d.caps = map[string]bool{"actions": true, "body": true}
	args := d.notifyArgs(7, msg)
	if args[0] != "linux-id" || args[1] != uint32(7) || args[2] != "icon" || args[3] != msg.Title {
		t.Errorf("header args = %v", args[:4])
	}
	if args[4] != msg.Body {
		t.Errorf("body escaped without body-markup: %q", args[4])
	}
	if got := args[5].([]string); len(got) != 2 || got[0] != "cancel" || got[1] != "Cancel" {
		t.Errorf("actions = %v", got)
	}
	hints := args[6].(map[string]dbus.Variant)
	if hints["urgency"].Value() != byte(1) || hints["transient"].Value() != true {
		t.Errorf("hints = %v", hints)
	}
	if args[7] != int32(30000) {
		t.Errorf("expire = %v", args[7])
	}

	d.caps = map[string]bool{"body-markup": true}
	args = d.notifyArgs(0, Message{Title: "t", Body: msg.Body, Cancelable: true})
	if args[4] != "for &lt;bob&gt; &amp; co" {
		t.Errorf("markup body = %q", args[4])
	}
	if got := args[5].([]string); len(got) != 0 {
		t.Errorf("actions without the capability = %v", got)
	}
	if args[7] != int32(-1) {
		t.Errorf("default expire = %v", args[7])
	}
}
