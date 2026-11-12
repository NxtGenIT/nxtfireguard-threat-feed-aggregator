package reconcile

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/config"
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/docker"
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/nfg"
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/services"
	"go.uber.org/zap"
)

// fakeDocker records calls and simulates container state.
type fakeDocker struct {
	containers map[string]*docker.Container
	specs      map[string]docker.Spec
	networks   map[string]bool
	logs       map[string]string
	runErr     error
	removeErr  map[string]error
	netErr     error
	legacyNets []string
	calls      []string
}

func newFake() *fakeDocker {
	return &fakeDocker{containers: map[string]*docker.Container{}, specs: map[string]docker.Spec{},
		networks: map[string]bool{TPotNetwork: true}, logs: map[string]string{}}
}

func (f *fakeDocker) List(context.Context) ([]docker.Container, error) {
	var out []docker.Container
	for _, c := range f.containers {
		out = append(out, *c)
	}
	return out, nil
}

func (f *fakeDocker) Run(_ context.Context, s docker.Spec) error {
	f.calls = append(f.calls, "run "+s.Name)
	if f.runErr != nil {
		return f.runErr
	}
	f.containers[s.Name] = &docker.Container{Name: s.Name, Running: true, Hash: s.Hash()}
	f.specs[s.Name] = s
	delete(f.logs, s.Name)
	return nil
}

func (f *fakeDocker) Remove(_ context.Context, name string) error {
	f.calls = append(f.calls, "rm "+name)
	if err := f.removeErr[name]; err != nil {
		return err
	}
	delete(f.containers, name)
	return nil
}

func (f *fakeDocker) RemoveLegacyNetworks(context.Context) ([]string, error) {
	f.calls = append(f.calls, "rm legacy networks")
	if f.netErr != nil {
		return nil, f.netErr
	}
	removed := f.legacyNets
	f.legacyNets = nil
	return removed, nil
}

func (f *fakeDocker) Logs(_ context.Context, name string, _ int) (string, error) {
	return f.logs[name], nil
}

func (f *fakeDocker) NetworkExists(_ context.Context, name string) (bool, error) {
	return f.networks[name], nil
}

func (f *fakeDocker) takeCalls() string {
	s := strings.Join(f.calls, ", ")
	f.calls = nil
	return s
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func setup(t *testing.T) (*Reconciler, *fakeDocker, *clock) {
	t.Helper()
	cfg := config.Config{
		Name: "agg-1", Key: "SECRET", CollectorURL: "https://collector.example", StateDir: t.TempDir(),
		ESTargets: []config.ESTarget{{URL: "http://es:9200", User: "elastic", Password: "espass"}},
	}
	f := newFake()
	c := &clock{t: time.Unix(1_000_000, 0)}
	r := New(f, cfg, zap.NewNop())
	r.now = c.now
	r.legacyDone = true // TestLegacy* cover the cleanup
	return r, f, c
}

var (
	ftd  = nfg.Settings{SyslogEnabled: true, SyslogServices: services.Toggles{CiscoFTD: true}}
	both = nfg.Settings{SyslogEnabled: true, SyslogServices: services.Toggles{CiscoFTD: true}, LogstashEnabled: true}
)

func TestStartsWantedContainersOnce(t *testing.T) {
	r, f, _ := setup(t)
	ctx := context.Background()

	st := r.Reconcile(ctx, both)
	if st.Healthy {
		t.Error("containers created this pass must not count as healthy yet")
	}
	if got := f.takeCalls(); got != "rm nfg-syslog, run nfg-syslog, rm nfg-logstash, run nfg-logstash" {
		t.Fatalf("calls = %s", got)
	}

	st = r.Reconcile(ctx, both)
	if !st.Healthy || len(st.Problems) != 0 {
		t.Fatalf("second pass: %+v", st)
	}
	if got := f.takeCalls(); got != "" {
		t.Fatalf("unchanged settings must not touch containers, got %s", got)
	}

	conf, err := os.ReadFile(filepath.Join(r.cfg.StateDir, "syslog-ng", "syslog-ng.conf"))
	if err != nil {
		t.Fatal(err)
	}
	pipeline, _ := os.ReadFile(filepath.Join(r.cfg.StateDir, "logstash", "logstash.conf"))
	for _, file := range [][]byte{conf, pipeline} {
		if strings.Contains(string(file), "SECRET") || strings.Contains(string(file), "espass") {
			t.Errorf("secret written to disk:\n%s", file)
		}
	}
	if s := f.specs[LogstashName]; s.Secrets["NFG_AUTH_KEY"] != "SECRET" || s.Secrets["NFG_ES_PASS_0"] != "espass" {
		t.Errorf("logstash secrets = %v", s.Secrets)
	}
	if got := f.specs[SyslogName].Ports; len(got) != 1 || got[0] != "514:514/udp" {
		t.Errorf("ports = %v", got)
	}
}

func TestOnlyChangedContainerIsRecreated(t *testing.T) {
	r, f, _ := setup(t)
	ctx := context.Background()
	r.Reconcile(ctx, both)
	f.takeCalls()

	more := both
	more.SyslogServices.CiscoISE = true
	r.Reconcile(ctx, more)
	if got := f.takeCalls(); got != "rm nfg-syslog, run nfg-syslog" {
		t.Fatalf("calls = %s", got)
	}
	if got := f.specs[SyslogName].Ports; len(got) != 2 || got[1] != "1025:1025/udp" {
		t.Errorf("ports = %v", got)
	}
}

func TestUnwantedContainersAreRemoved(t *testing.T) {
	r, f, _ := setup(t)
	ctx := context.Background()
	r.Reconcile(ctx, both)
	f.takeCalls()

	// Syslog on but no service selected means no syslog container.
	st := r.Reconcile(ctx, nfg.Settings{SyslogEnabled: true})
	if got := f.takeCalls(); !strings.Contains(got, "rm nfg-syslog") || !strings.Contains(got, "rm nfg-logstash") || strings.Contains(got, "run") {
		t.Fatalf("calls = %s", got)
	}
	if !st.Healthy {
		t.Errorf("nothing wanted is healthy: %+v", st)
	}
}

func TestCrashLoopBacksOff(t *testing.T) {
	r, f, clk := setup(t)
	ctx := context.Background()
	r.Reconcile(ctx, ftd)
	r.Reconcile(ctx, ftd)
	f.takeCalls()

	var restarts []time.Duration
	start := clk.t
	for i := 0; i < 60; i++ {
		f.containers[SyslogName].Running = false
		r.Reconcile(ctx, ftd)
		if strings.Contains(f.takeCalls(), "run") {
			restarts = append(restarts, clk.t.Sub(start))
		}
		clk.advance(30 * time.Second)
	}
	want := []time.Duration{0, 30 * time.Second, 90 * time.Second, 210 * time.Second, 450 * time.Second, 930 * time.Second, 1530 * time.Second}
	for i, w := range want {
		if i >= len(restarts) || restarts[i] != w {
			t.Fatalf("restarts at %v, want prefix %v", restarts, want)
		}
	}
}

func TestBackoffResetsWhenStable(t *testing.T) {
	r, f, clk := setup(t)
	ctx := context.Background()
	r.Reconcile(ctx, ftd)
	f.containers[SyslogName].Running = false
	r.Reconcile(ctx, ftd) // restart, backoff 30s
	clk.advance(stableAfter)
	r.Reconcile(ctx, ftd) // healthy for stableAfter
	f.takeCalls()
	f.containers[SyslogName].Running = false
	r.Reconcile(ctx, ftd)
	if got := f.takeCalls(); !strings.Contains(got, "run") {
		t.Fatalf("restart after a stable run must be immediate, calls = %q", got)
	}
}

// A container that crashes a minute after every start looks healthy at one
// check in between; that must not reset the backoff.
func TestShortRecoveryKeepsBackoff(t *testing.T) {
	r, f, clk := setup(t)
	ctx := context.Background()
	r.Reconcile(ctx, ftd)
	var restarts int
	for range 20 {
		f.containers[SyslogName].Running = false
		r.Reconcile(ctx, ftd)
		if strings.Contains(f.takeCalls(), "run") {
			restarts++
		}
		clk.advance(time.Minute)
		r.Reconcile(ctx, ftd) // up again for a moment
		clk.advance(time.Minute)
	}
	// 40 minutes: with backoff 30s, 1m, 2m, 4m, 8m, 10m... that is about 7
	// restarts, not 20.
	if restarts > 8 {
		t.Fatalf("%d restarts in 40 minutes: backoff was reset by a short recovery", restarts)
	}
}

func TestLogstashUnknownHostTriggersRestart(t *testing.T) {
	r, f, _ := setup(t)
	ctx := context.Background()
	s := nfg.Settings{LogstashEnabled: true}
	r.Reconcile(ctx, s)
	f.takeCalls()
	f.logs[LogstashName] = "[ERROR] java.net.UnknownHostException: es"
	st := r.Reconcile(ctx, s)
	if st.Healthy || f.takeCalls() != "rm nfg-logstash, run nfg-logstash" {
		t.Fatalf("status %+v", st)
	}
}

func TestDockerUnhealthyTriggersRestart(t *testing.T) {
	r, f, _ := setup(t)
	ctx := context.Background()
	r.Reconcile(ctx, ftd)
	f.takeCalls()
	f.containers[SyslogName].Health = "starting"
	if st := r.Reconcile(ctx, ftd); !st.Healthy {
		t.Fatalf("starting counts as healthy: %+v", st)
	}
	f.containers[SyslogName].Health = "unhealthy"
	r.Reconcile(ctx, ftd)
	if got := f.takeCalls(); got != "rm nfg-syslog, run nfg-syslog" {
		t.Fatalf("calls = %s", got)
	}
}

func TestLogstashNeedsTPotNetwork(t *testing.T) {
	r, f, _ := setup(t)
	delete(f.networks, TPotNetwork)
	st := r.Reconcile(context.Background(), nfg.Settings{LogstashEnabled: true})
	if st.Healthy || !strings.Contains(strings.Join(st.Problems, ";"), TPotNetwork) {
		t.Fatalf("status %+v", st)
	}
	if got := f.takeCalls(); strings.Contains(got, "run") {
		t.Fatalf("must not start without network: %s", got)
	}
}

func TestLogstashWithoutTargetsIsAProblem(t *testing.T) {
	r, f, _ := setup(t)
	ctx := context.Background()
	r.Reconcile(ctx, nfg.Settings{LogstashEnabled: true})
	f.takeCalls()
	r.cfg.ESTargets = nil
	st := r.Reconcile(ctx, nfg.Settings{LogstashEnabled: true})
	if st.Healthy || f.takeCalls() != "rm nfg-logstash" {
		t.Fatalf("status %+v", st)
	}
}

func TestRunFailureIsReported(t *testing.T) {
	r, f, _ := setup(t)
	f.runErr = fmt.Errorf("port is already allocated")
	st := r.Reconcile(context.Background(), ftd)
	if st.Healthy || !strings.Contains(st.Problems[0], "port is already allocated") {
		t.Fatalf("status %+v", st)
	}
}

func TestLegacyCleanupKeepsManagedAndRunsOnce(t *testing.T) {
	r, f, _ := setup(t)
	ctx := context.Background()
	r.Reconcile(ctx, ftd)
	f.takeCalls()
	r.legacyDone = false
	f.legacyNets = []string{"nfgtfa-1_default"}
	r.Reconcile(ctx, ftd)
	// Containers first: a network in use cannot be removed.
	if got := f.takeCalls(); got != "rm nfg-logstash, rm legacy networks" {
		t.Fatalf("calls = %s", got)
	}
	r.Reconcile(ctx, ftd)
	if got := f.takeCalls(); got != "" {
		t.Fatalf("cleanup must not repeat after it succeeded, calls = %s", got)
	}
}

func TestLegacyCleanupIsRetried(t *testing.T) {
	r, f, _ := setup(t)
	ctx := context.Background()
	r.legacyDone = false
	f.removeErr = map[string]error{LogstashName: fmt.Errorf("Cannot connect to the Docker daemon")}
	st := r.Reconcile(ctx, nfg.Settings{})
	if st.Healthy || !strings.Contains(strings.Join(st.Problems, ";"), "previous version") {
		t.Fatalf("status %+v", st)
	}
	f.takeCalls()
	f.removeErr = nil
	f.netErr = fmt.Errorf("network nfgtfa-1_default has active endpoints")
	if st := r.Reconcile(ctx, nfg.Settings{}); st.Healthy {
		t.Fatalf("network cleanup failure must be reported: %+v", st)
	}
	f.netErr = nil
	if st := r.Reconcile(ctx, nfg.Settings{}); !st.Healthy {
		t.Fatalf("status %+v", st)
	}
	if !r.legacyDone {
		t.Fatal("cleanup not marked done")
	}
}

func TestSyslogRejectsUnrepresentableSecret(t *testing.T) {
	r, f, _ := setup(t)
	r.cfg.Key = `abc"def`
	st := r.Reconcile(context.Background(), both)
	if st.Healthy || !strings.Contains(strings.Join(st.Problems, ";"), "AUTH_SECRET") {
		t.Fatalf("status %+v", st)
	}
	if got := f.takeCalls(); strings.Contains(got, "run nfg-syslog") || !strings.Contains(got, "run nfg-logstash") {
		t.Fatalf("syslog must not start, logstash (env-substituted) may: %s", got)
	}
}

func TestSyslogHasHealthCheck(t *testing.T) {
	r, f, _ := setup(t)
	r.Reconcile(context.Background(), ftd)
	if got := strings.Join(f.specs[SyslogName].HealthCmd, " "); got != "syslog-ng-ctl stats -c /config/syslog-ng.ctl" {
		t.Fatalf("health cmd = %q", got)
	}
}
