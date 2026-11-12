package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/config"
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/docker"
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/nfg"
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/state"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

type fakeDocker struct {
	mu    sync.Mutex
	specs map[string]docker.Spec
}

func (f *fakeDocker) List(context.Context) ([]docker.Container, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []docker.Container
	for name, s := range f.specs {
		out = append(out, docker.Container{Name: name, Running: true, Hash: s.Hash()})
	}
	return out, nil
}

func (f *fakeDocker) Run(_ context.Context, s docker.Spec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.specs[s.Name] = s
	return nil
}

func (f *fakeDocker) Remove(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.specs, name)
	return nil
}

func (f *fakeDocker) Logs(context.Context, string, int) (string, error)      { return "", nil }
func (f *fakeDocker) NetworkExists(context.Context, string) (bool, error)    { return true, nil }
func (f *fakeDocker) RemoveLegacyNetworks(context.Context) ([]string, error) { return nil, nil }

func (f *fakeDocker) ports(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.specs[name]
	if !ok {
		return "-"
	}
	return strings.Join(s.Ports, ",")
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The whole loop against a fake controller: initial sync starts syslog,
// a push changes it, heartbeats flow while healthy, shutdown cleans up.
func TestRun(t *testing.T) {
	checkEvery = 20 * time.Millisecond
	push := make(chan string)
	var heartbeats atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sync/config":
			_, _ = w.Write([]byte(`{"config":{"syslogEnabled":true,"syslogServices":{"syslogCiscoFtdEnabled":true}}}`))
		case "/sync/ws/updates":
			conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			for msg := range push {
				_ = conn.WriteMessage(websocket.TextMessage, []byte(msg))
			}
		case "/ping/hb":
			heartbeats.Add(1)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := config.Config{
		Name: "agg-1", Key: "k", HeartbeatID: "hb", StateDir: t.TempDir(),
		HeartbeatURL: srv.URL, ControllerURL: srv.URL, CollectorURL: "https://collector.example",
		ControllerWSURL: "ws" + strings.TrimPrefix(srv.URL, "http") + "/sync/ws/updates",
	}
	fake := &fakeDocker{specs: map[string]docker.Spec{}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { run(ctx, cfg, zap.NewNop(), fake); close(done) }()

	eventually(t, "syslog with FTD", func() bool { return fake.ports("nfg-syslog") == "514:514/udp" })
	eventually(t, "a heartbeat", func() bool { return heartbeats.Load() > 0 })

	push <- `{"type":"config-update","syslogEnabled":true,"syslogServices":{"syslogCiscoFtdEnabled":true,"syslogCiscoIseEnabled":true}}`
	eventually(t, "pushed settings", func() bool { return fake.ports("nfg-syslog") == "514:514/udp,1025:1025/udp" })

	var saved nfg.Settings
	eventually(t, "saved settings", func() bool {
		ok, _ := state.Dir(cfg.StateDir).LoadJSON(state.SettingsFile, &saved)
		return ok && saved.SyslogServices.CiscoISE
	})

	close(push)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return")
	}
	if p := fake.ports("nfg-syslog"); p != "-" {
		t.Fatalf("container left after shutdown: %s", p)
	}
}
