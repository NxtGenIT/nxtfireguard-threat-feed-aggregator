package nfg

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
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/services"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

func client(srvURL string) *Client {
	c := New(config.Config{
		Name: "agg-1", Key: "SECRET", HeartbeatID: "hb-1",
		ControllerURL: srvURL, HeartbeatURL: srvURL,
		ControllerWSURL: "ws" + strings.TrimPrefix(srvURL, "http") + "/sync/ws/updates",
	})
	c.retryDelay = time.Millisecond
	return c
}

func TestFetchSettings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sync/config" || r.Header.Get("X_AUTH_KEY") != "SECRET" || r.Header.Get("X_AGGREGATOR_NAME") != "agg-1" {
			t.Errorf("request %s %v", r.URL.Path, r.Header)
		}
		_, _ = w.Write([]byte(`{"config":{"name":"agg-1","syslogEnabled":true,"logstashEnabled":true,
			"syslogServices":{"syslogCiscoFtdEnabled":true,"syslogPfsenseEnabled":true}}}`))
	}))
	defer srv.Close()

	s, err := client(srv.URL).FetchSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := Settings{SyslogEnabled: true, LogstashEnabled: true, SyslogServices: services.Toggles{CiscoFTD: true, PfSense: true}}
	if s != want {
		t.Fatalf("got %+v", s)
	}
}

func TestRetriesServerErrorsOnly(t *testing.T) {
	for _, tc := range []struct {
		status    int
		wantCalls int32
	}{{500, 4}, {502, 4}, {401, 1}, {404, 1}} {
		var calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.WriteHeader(tc.status)
		}))
		_, err := client(srv.URL).FetchSettings(context.Background())
		srv.Close()
		if err == nil || calls.Load() != tc.wantCalls {
			t.Errorf("status %d: err=%v calls=%d, want %d", tc.status, err, calls.Load(), tc.wantCalls)
		}
	}
}

func TestRecoversAfterServerError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(503)
			return
		}
		_, _ = w.Write([]byte(`{"config":{"syslogEnabled":true}}`))
	}))
	defer srv.Close()
	s, err := client(srv.URL).FetchSettings(context.Background())
	if err != nil || !s.SyslogEnabled {
		t.Fatalf("s=%+v err=%v", s, err)
	}
}

func TestHeartbeat(t *testing.T) {
	var got *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r }))
	defer srv.Close()
	if err := client(srv.URL).Heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got.URL.Path != "/ping/hb-1" || got.Header.Get("apikey") != "SECRET" {
		t.Fatalf("request %s %v", got.URL.Path, got.Header)
	}
}

// The stream resyncs on every connect, applies config pushes, and comes back
// after the server drops it.
func TestWatchReconnectsAndResyncs(t *testing.T) {
	var conns atomic.Int32
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sync/ws/updates" || r.Header.Get("X_AUTH_KEY") != "SECRET" {
			t.Errorf("ws request %s %v", r.URL.Path, r.Header)
		}
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		if conns.Add(1) == 1 {
			_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"config-update","name":"agg-1","syslogEnabled":true,"syslogServices":{"syslogSuricataEnabled":true},"logstashEnabled":false}`))
			_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"something-else"}`))
			return // drop the connection
		}
		_, _, _ = conn.ReadMessage() // hold until the client leaves
	}))
	defer srv.Close()

	var mu sync.Mutex
	var resyncs int
	var applied []Settings
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		client(srv.URL).Watch(ctx, zap.NewNop(), func() { mu.Lock(); resyncs++; mu.Unlock() },
			func(s Settings) { mu.Lock(); applied = append(applied, s); mu.Unlock() })
		close(done)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		ok := conns.Load() >= 2 && resyncs >= 3 && len(applied) == 1
		mu.Unlock()
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("conns=%d resyncs=%d applied=%v", conns.Load(), resyncs, applied)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if want := (Settings{SyslogEnabled: true, SyslogServices: services.Toggles{Suricata: true}}); applied[0] != want {
		t.Errorf("applied %+v", applied[0])
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Watch did not return after cancel")
	}
}
