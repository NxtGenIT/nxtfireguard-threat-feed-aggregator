package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func base() map[string]string {
	return map[string]string{"AGGREGATOR_NAME": "agg-1", "AUTH_SECRET": "s3cret", "HEARTBEAT_IDENTIFIER": "hb"}
}

func TestDefaults(t *testing.T) {
	c, warnings, err := Load(env(base()))
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Errorf("warnings: %v", warnings)
	}
	checks := map[string]string{
		c.ControllerURL:   "https://controller.collector.nxtfireguard.de",
		c.ControllerWSURL: "wss://controller.collector.nxtfireguard.de/sync/ws/updates",
		c.CollectorURL:    "https://threat.collector.nxtfireguard.de",
		c.HeartbeatURL:    "https://heartbeat.nxtfireguard.de",
	}
	for got, want := range checks {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
	if !strings.HasSuffix(c.StateDir, "nfgtfa-state") || !filepath.IsAbs(c.StateDir) {
		t.Errorf("StateDir = %q", c.StateDir)
	}
}

func TestRequired(t *testing.T) {
	_, _, err := Load(env(map[string]string{}))
	if err == nil || !strings.Contains(err.Error(), "AGGREGATOR_NAME") || !strings.Contains(err.Error(), "AUTH_SECRET") {
		t.Fatalf("err = %v", err)
	}
}

func TestWebsocketURL(t *testing.T) {
	cases := []struct{ url, host, want string }{
		{"https://c.example", "", "wss://c.example/sync/ws/updates"},
		{"http://localhost:8080/", "", "ws://localhost:8080/sync/ws/updates"},
		{"https://c.example", "other:9443", "wss://other:9443/sync/ws/updates"},
	}
	for _, tc := range cases {
		m := base()
		m["NFG_TFA_CONTROLLER_URL"] = tc.url
		m["NFG_TFA_CONTROLLER_HOST"] = tc.host
		c, _, err := Load(env(m))
		if err != nil {
			t.Fatal(err)
		}
		if c.ControllerWSURL != tc.want {
			t.Errorf("%s + %q: got %s, want %s", tc.url, tc.host, c.ControllerWSURL, tc.want)
		}
	}
	m := base()
	m["NFG_TFA_CONTROLLER_URL"] = "controller.example"
	if _, _, err := Load(env(m)); err == nil {
		t.Error("want error for a URL without scheme")
	}
}

func TestElasticsearchTargets(t *testing.T) {
	m := base()
	m["ELASTICSEARCH_TARGETS"] = `'[{"url":"http://es1:9200","user":"foo","pass":"bar"},{"url":"http://es2:9200"}]'`
	c, _, err := Load(env(m))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.ESTargets) != 2 || c.ESTargets[0].User != "foo" || c.ESTargets[0].Password.Reveal() != "bar" {
		t.Fatalf("targets = %#v", c.ESTargets)
	}
	m["ELASTICSEARCH_TARGETS"] = `{"url":1}`
	if _, _, err := Load(env(m)); err == nil {
		t.Error("want error for invalid JSON")
	}
}

func TestIgnoredLokiSettingsWarn(t *testing.T) {
	m := base()
	m["LOG_TO_LOKI"] = "true"
	_, warnings, _ := Load(env(m))
	if len(warnings) != 1 || !strings.Contains(warnings[0], "LOG_TO_LOKI") {
		t.Fatalf("warnings = %v", warnings)
	}
}

func TestSecretNeverPrinted(t *testing.T) {
	m := base()
	m["ELASTICSEARCH_TARGETS"] = `[{"url":"http://es","user":"u","pass":"espass"}]`
	c, _, err := Load(env(m))
	if err != nil {
		t.Fatal(err)
	}
	j, _ := json.Marshal(c)
	var buf bytes.Buffer
	enc := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	log := zap.New(zapcore.NewCore(enc, zapcore.AddSync(&buf), zap.DebugLevel))
	log.Info("cfg", zap.Any("config", c), zap.Stringer("key", c.Key))
	_ = log.Sync()
	outputs := []string{fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), string(j), buf.String()}
	for _, out := range outputs {
		if strings.Contains(out, "s3cret") || strings.Contains(out, "espass") {
			t.Errorf("secret leaked: %s", out)
		}
	}
}
