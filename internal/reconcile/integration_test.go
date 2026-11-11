//go:build docker

package reconcile

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/config"
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/docker"
	"go.uber.org/zap"
)

// TestIntegrationSyslogGetsKeyFromEnvironment starts the real syslog-ng container
// and asks the running daemon for its preprocessed config, which shows whether
// the `NFG_AUTH_KEY` reference was filled in from the container environment.
func TestIntegrationSyslogGetsKeyFromEnvironment(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	// Docker VMs on macOS (colima, Docker Desktop) share only the home
	// directory by default, so the state dir must not be in the system temp.
	stateDir, err := os.MkdirTemp(".", "it-state-")
	if err != nil {
		t.Fatal(err)
	}
	stateDir, _ = filepath.Abs(stateDir)
	defer os.RemoveAll(stateDir)
	cfg := config.Config{Name: "agg-it", Key: "it-secret-123", CollectorURL: "http://collector.invalid", StateDir: stateDir}
	r := New(docker.CLI{}, cfg, zap.NewNop())
	defer r.RemoveAll(context.Background())

	st := r.Reconcile(ctx, ftd)
	if len(st.Problems) != 1 || !strings.HasSuffix(st.Problems[0], "started") {
		t.Fatalf("first pass: %+v", st)
	}
	var out []byte
	for ctx.Err() == nil {
		out, err = exec.CommandContext(ctx, "docker", "exec", SyslogName, "syslog-ng-ctl", "config", "--preprocessed", "-c", "/config/syslog-ng.ctl").CombinedOutput()
		if err == nil && strings.Contains(string(out), "d_http_firepower") {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		logs, _ := exec.Command("docker", "logs", SyslogName).CombinedOutput()
		t.Fatalf("syslog-ng-ctl: %v\n%s\nlogs:\n%s", err, out, logs)
	}
	if !strings.Contains(string(out), `"X-AUTH_KEY: it-secret-123"`) {
		t.Fatalf("auth key not substituted:\n%s", out)
	}

	if st := r.Reconcile(ctx, ftd); !st.Healthy {
		t.Fatalf("running container not healthy: %+v", st)
	}
	r.RemoveAll(ctx)
	if cs, _ := (docker.CLI{}).List(ctx); len(cs) != 0 {
		t.Fatalf("containers left after RemoveAll: %+v", cs)
	}
}
