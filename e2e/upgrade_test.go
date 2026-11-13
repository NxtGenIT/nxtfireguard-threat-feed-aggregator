//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestUpgradeFromV1 runs a real 1.x release (docker compose based) until its
// relay is up, kills it the way a crash or a hard stop would (so its
// container and compose network stay behind), then starts this build on the
// same host. NFGTFA_V1_BINARY points at the old binary; CI downloads v1.0.9.
func TestUpgradeFromV1(t *testing.T) {
	v1 := os.Getenv("NFGTFA_V1_BINARY")
	if v1 == "" {
		t.Skip("NFGTFA_V1_BINARY not set")
	}
	b := newBackend(t, ftdOnly)
	work := t.TempDir()
	// 1.x refuses to start without a .env in its working directory.
	if err := os.WriteFile(filepath.Join(work, ".env"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	env := Env(b, t.TempDir())
	env["NFG_TFA_CONTROLLER_HOST"] = strings.TrimPrefix(env["NFG_TFA_CONTROLLER_URL"], "http://")
	env["SKIP_VERIFY_TLS"] = "true" // 1.x uses ws:// only then
	env["LOG_TO_LOKI"] = "false"

	old := StartAggregator(t, v1, work, env)
	waitFor(t, 3*time.Minute, "1.x relay running", func() bool {
		c := Inspect(t, syslogName)
		return c != nil && c.State.Running && !c.Managed()
	})
	if legacyNetworks(t) == 0 {
		t.Fatal("1.x left no compose network; the test does not reproduce an upgrade")
	}
	old.Kill()

	a := StartAggregator(t, "", work, env)
	waitRunning(t, syslogName, 3*time.Minute)
	waitFor(t, 30*time.Second, "1.x compose network removed", func() bool { return legacyNetworks(t) == 0 })
	if len(a.LogLines("removed networks left by older versions")) == 0 {
		t.Error("legacy cleanup not logged")
	}
	got := deliver(t, b, 514, marker("upgraded"), time.Minute, ftdLine(marker("upgraded")))
	if got.Header.Get("X-AUTH_KEY") != b.Secret {
		t.Fatalf("X-AUTH_KEY %q after upgrade", got.Header.Get("X-AUTH_KEY"))
	}
	waitFor(t, 30*time.Second, "heartbeat after upgrade", func() bool {
		for _, h := range b.Heartbeats() {
			if h.At.After(Inspect(t, syslogName).State.StartedAt) {
				return true
			}
		}
		return false
	})
}

func legacyNetworks(t *testing.T) int {
	n := 0
	for _, name := range strings.Fields(docker(t, "network", "ls", "--format", "{{.Name}}")) {
		if strings.HasPrefix(name, "nfgtfa-") && strings.HasSuffix(name, "_default") {
			n++
		}
	}
	return n
}
