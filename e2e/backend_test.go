//go:build e2e

package e2e

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// Settings is the dashboard configuration the fake controller hands out, in
// the tfa-controller's wire format (handlers/syncConfig.go, kafka/consumer.go
// in the main repo).
type Settings struct {
	SyslogEnabled   bool     `json:"syslogEnabled"`
	SyslogServices  Services `json:"syslogServices"`
	LogstashEnabled bool     `json:"logstashEnabled"`
}

type Services struct {
	CiscoFTD bool `json:"syslogCiscoFtdEnabled"`
	CiscoISE bool `json:"syslogCiscoIseEnabled"`
	OPNsense bool `json:"syslogOpnsenseEnabled"`
	PfSense  bool `json:"syslogPfsenseEnabled"`
	Suricata bool `json:"syslogSuricataEnabled"`
}

// Request is one request the fake received.
type Request struct {
	At     time.Time
	Method string
	Path   string
	Header http.Header
	Body   string
	Status int // what the fake answered
}

// Backend plays the tfa-controller (GET /sync/config, the /sync/ws/updates
// stream), the heartbeat monitor (GET /ping/<id>) and the threat collector
// (POST /<route>) on one port. It listens on every interface, so containers
// reach it through the docker bridge gateway.
type Backend struct {
	t      *testing.T
	Name   string
	Secret string
	HBID   string
	URL    string // as seen from the host
	Port   int

	srv *http.Server

	mu         sync.Mutex
	settings   Settings
	down       bool // controller answers 503 and refuses the stream
	conns      map[*websocket.Conn]bool
	connects   int
	heartbeats []Request
	collected  []Request
	syncs      []Request
	// respond decides the collector's answer; nil means 200.
	respond  func(r Request, attempt int) int
	attempts map[string]int // body -> times seen
}

func NewBackend(t *testing.T, name, secret, hbID string, s Settings) *Backend {
	t.Helper()
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &Backend{t: t, Name: name, Secret: secret, HBID: hbID, settings: s,
		conns: map[*websocket.Conn]bool{}, attempts: map[string]int{}}
	b.Port = ln.Addr().(*net.TCPAddr).Port
	b.srv = &http.Server{Handler: http.HandlerFunc(b.serve), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = b.srv.Serve(ln) }()
	t.Cleanup(func() {
		b.DropStreams()
		_ = b.srv.Close()
	})
	return b
}

var upgrader = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

func (b *Backend) authorized(r *http.Request) bool {
	return r.Header.Get("X_AUTH_KEY") == b.Secret && r.Header.Get("X_AGGREGATOR_NAME") == b.Name
}

func (b *Backend) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	req := Request{At: time.Now(), Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone(), Body: string(body)}

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/sync/config":
		b.mu.Lock()
		down, s := b.down, b.settings
		b.syncs = append(b.syncs, req)
		b.mu.Unlock()
		switch {
		case down:
			w.WriteHeader(http.StatusServiceUnavailable)
		case !b.authorized(r):
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"config": map[string]any{
				"name": b.Name, "syslogEnabled": s.SyslogEnabled,
				"syslogServices": s.SyslogServices, "logstashEnabled": s.LogstashEnabled,
			}})
		}

	case r.Method == http.MethodGet && r.URL.Path == "/sync/ws/updates":
		b.mu.Lock()
		down := b.down
		b.mu.Unlock()
		if down {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if !b.authorized(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		b.mu.Lock()
		b.conns[c] = true
		b.connects++
		b.mu.Unlock()
		// Read until the client goes away, answering pings.
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				break
			}
		}
		b.mu.Lock()
		delete(b.conns, c)
		b.mu.Unlock()
		_ = c.Close()

	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/ping/"):
		b.mu.Lock()
		b.heartbeats = append(b.heartbeats, req)
		b.mu.Unlock()
		if r.Header.Get("apikey") != b.Secret || r.URL.Path != "/ping/"+b.HBID {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)

	case r.Method == http.MethodPost:
		b.mu.Lock()
		b.attempts[req.Body]++
		attempt := b.attempts[req.Body]
		status := http.StatusOK
		if b.respond != nil {
			status = b.respond(req, attempt)
		}
		req.Status = status
		b.collected = append(b.collected, req)
		b.mu.Unlock()
		w.WriteHeader(status)

	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// SetSettings changes what /sync/config returns; it does not push.
func (b *Backend) SetSettings(s Settings) {
	b.mu.Lock()
	b.settings = s
	b.mu.Unlock()
}

// Push sends a config-update to every open stream, as the controller does
// when the dashboard changes, and makes it the synced settings too.
func (b *Backend) Push(s Settings) {
	b.t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings = s
	if len(b.conns) == 0 {
		b.t.Fatal("push: no open update stream")
	}
	msg, _ := json.Marshal(map[string]any{
		"type": "config-update", "name": b.Name, "syslogEnabled": s.SyslogEnabled,
		"syslogServices": s.SyslogServices, "logstashEnabled": s.LogstashEnabled,
	})
	for c := range b.conns {
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := c.WriteMessage(websocket.TextMessage, msg); err != nil {
			b.t.Fatalf("push: %v", err)
		}
	}
}

// SetDown makes the controller unreachable (503, stream refused) or back.
func (b *Backend) SetDown(down bool) {
	b.mu.Lock()
	b.down = down
	b.mu.Unlock()
	if down {
		b.DropStreams()
	}
}

// DropStreams closes every open update stream from the server side.
func (b *Backend) DropStreams() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for c := range b.conns {
		_ = c.Close()
	}
}

// RespondWith scripts the collector's status codes.
func (b *Backend) RespondWith(f func(r Request, attempt int) int) {
	b.mu.Lock()
	b.respond = f
	b.mu.Unlock()
}

func (b *Backend) Streams() (open, total int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.conns), b.connects
}

func (b *Backend) Heartbeats() []Request {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Request(nil), b.heartbeats...)
}

func (b *Backend) Syncs() []Request {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Request(nil), b.syncs...)
}

// Collected returns what the collector received, optionally only requests
// whose body contains marker.
func (b *Backend) Collected(marker string) []Request {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []Request
	for _, r := range b.collected {
		if marker == "" || strings.Contains(r.Body, marker) {
			out = append(out, r)
		}
	}
	return out
}
