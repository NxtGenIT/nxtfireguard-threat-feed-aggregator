//go:build e2e

// Package e2e runs the real nfgtfa binary against a fake NxtFireGuard
// backend and the real docker daemon: real syslog-ng (and, in the T-Pot
// test, Logstash and Elasticsearch) containers, real UDP syslog in, real
// HTTP out. See the Testing section of the README.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	// The loop runs every checkEvery (main.checkEveryOverride) instead of
	// every minute.
	checkEvery = 2 * time.Second

	syslogName   = "nfg-syslog"
	logstashName = "nfg-logstash"
)

var (
	binary  string // the aggregator under test
	hostIP  string // the host as containers on the default bridge see it
	repoDir string
)

func TestMain(m *testing.M) {
	os.Exit(func() int {
		if out, err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "e2e tests need a running docker daemon: %v\n%s", err, out)
			return 1
		}
		gw, err := exec.Command("docker", "network", "inspect", "bridge", "--format", "{{(index .IPAM.Config 0).Gateway}}").Output()
		if err != nil {
			fmt.Fprintln(os.Stderr, "docker bridge gateway:", err)
			return 1
		}
		hostIP = strings.TrimSpace(string(gw))

		tmp, err := os.MkdirTemp("", "nfgtfa-e2e-bin-")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer func() { _ = os.RemoveAll(tmp) }()
		repoDir, _ = filepath.Abs("..")
		binary = filepath.Join(tmp, "nfgtfa")
		build := exec.Command("go", "build", "-race",
			"-ldflags", "-X main.checkEveryOverride="+checkEvery.String()+" -X main.version=e2e",
			"-o", binary, "./cmd/aggregator")
		build.Dir = repoDir
		if out, err := build.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "build: %v\n%s", err, out)
			return 1
		}
		cleanDocker()
		defer cleanDocker()
		return m.Run()
	}())
}

// cleanDocker removes everything an aggregator (any version) may leave.
func cleanDocker() {
	_ = exec.Command("docker", "rm", "-f", syslogName, logstashName).Run()
	out, _ := exec.Command("docker", "network", "ls", "--format", "{{.Name}}").Output()
	for _, n := range strings.Fields(string(out)) {
		if strings.HasPrefix(n, "nfgtfa-") && strings.HasSuffix(n, "_default") {
			_ = exec.Command("docker", "network", "rm", n).Run()
		}
	}
}

// waitFor polls cond until it holds or timeout passes.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", timeout, what)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// never fails if cond becomes true within d.
func never(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			t.Fatalf("unexpected: %s", what)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// Agg is one running aggregator process.
type Agg struct {
	t    *testing.T
	cmd  *exec.Cmd
	logs *lockedBuffer
	done chan struct{}
	err  error
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// Env is the aggregator's environment for backend b with its state in dir.
func Env(b *Backend, dir string) map[string]string {
	local := fmt.Sprintf("http://127.0.0.1:%d", b.Port)
	return map[string]string{
		"AGGREGATOR_NAME":          b.Name,
		"AUTH_SECRET":              b.Secret,
		"HEARTBEAT_IDENTIFIER":     b.HBID,
		"HEARTBEAT_URL":            local,
		"NFG_TFA_CONTROLLER_URL":   local,
		"THREAT_LOG_COLLECTOR_URL": fmt.Sprintf("http://%s:%d", hostIP, b.Port),
		"NFG_STATE_DIR":            filepath.Join(dir, "state"),
		"DEBUG":                    "true",
	}
}

// StartAggregator runs bin (the build under test if empty) in dir.
func StartAggregator(t *testing.T, bin, dir string, env map[string]string) *Agg {
	t.Helper()
	if bin == "" {
		bin = binary
	}
	a := &Agg{t: t, logs: &lockedBuffer{}, done: make(chan struct{})}
	a.cmd = exec.Command(bin)
	a.cmd.Dir = dir
	a.cmd.Env = os.Environ()
	for k, v := range env {
		a.cmd.Env = append(a.cmd.Env, k+"="+v)
	}
	a.cmd.Stdout = a.logs
	a.cmd.Stderr = a.logs
	if err := a.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		a.err = a.cmd.Wait()
		close(a.done)
	}()
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("aggregator (%s) output:\n%s", filepath.Base(bin), a.logs.String())
			diagnose(t)
		}
		a.Kill()
		cleanDocker()
	})
	return a
}

// Exited reports whether the process has ended.
func (a *Agg) Exited() bool {
	select {
	case <-a.done:
		return true
	default:
		return false
	}
}

// Stop sends sig and waits up to timeout for the process to end.
func (a *Agg) Stop(sig syscall.Signal, timeout time.Duration) error {
	a.t.Helper()
	_ = a.cmd.Process.Signal(sig)
	select {
	case <-a.done:
		return a.err
	case <-time.After(timeout):
		a.t.Fatalf("aggregator still running %s after %v", timeout, sig)
		return nil
	}
}

func (a *Agg) Kill() {
	if !a.Exited() {
		_ = a.cmd.Process.Kill()
		<-a.done
	}
}

// LogLines returns the JSON log entries whose msg contains substr.
func (a *Agg) LogLines(substr string) []map[string]any {
	var out []map[string]any
	sc := bufio.NewScanner(strings.NewReader(a.logs.String()))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e map[string]any
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		if msg, _ := e["msg"].(string); strings.Contains(msg, substr) {
			out = append(out, e)
		}
	}
	return out
}

// Container is what the tests look at in docker inspect.
type Container struct {
	ID    string
	State struct {
		Running   bool
		Status    string
		StartedAt time.Time
		Health    *struct{ Status string }
	}
	Config struct {
		Labels map[string]string
	}
	NetworkSettings struct {
		Ports    map[string]any
		Networks map[string]any
	}
}

// Inspect returns the container, or nil if it does not exist.
func Inspect(t *testing.T, name string) *Container {
	t.Helper()
	out, err := exec.Command("docker", "inspect", "--type", "container", name).Output()
	if err != nil {
		return nil
	}
	var cs []Container
	if err := json.Unmarshal(out, &cs); err != nil || len(cs) != 1 {
		t.Fatalf("docker inspect %s: %v", name, err)
	}
	return &cs[0]
}

func (c *Container) Managed() bool { return c != nil && c.Config.Labels["nfg.managed"] == "true" }

func (c *Container) Health() string {
	if c == nil || c.State.Health == nil {
		return ""
	}
	return c.State.Health.Status
}

// UDPPorts lists the published UDP ports, e.g. "514/udp".
func (c *Container) UDPPorts() []string {
	var out []string
	for p, bindings := range c.NetworkSettings.Ports {
		if strings.HasSuffix(p, "/udp") && bindings != nil {
			out = append(out, p)
		}
	}
	return out
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// sendSyslog sends each line as one UDP datagram to the published port.
func sendSyslog(t *testing.T, port int, lines ...string) {
	t.Helper()
	c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	for _, l := range lines {
		if _, err := c.Write([]byte(l)); err != nil {
			t.Fatal(err)
		}
	}
}

// deliver sends lines (the last one carrying marker) until the collector
// has a request containing marker. UDP gives no feedback, and syslog-ng
// may not listen yet right after its container started, so a round may be
// lost. Lines are re-sent as a group, so anything sent before marker in the
// same round was processed before it.
func deliver(t *testing.T, b *Backend, port int, marker string, lines ...string) Request {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for {
		sendSyslog(t, port, lines...)
		for wait := time.Now().Add(3 * time.Second); time.Now().Before(wait); time.Sleep(100 * time.Millisecond) {
			if got := b.Collected(marker); len(got) > 0 {
				return got[0]
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("collector never received %q (sent to udp/%d)", marker, port)
		}
	}
}

func rfc3164(pri int, host, tag, msg string) string {
	return fmt.Sprintf("<%d>%s %s %s %s", pri, time.Now().Format(time.Stamp), host, tag, msg)
}

func marker(what string) string {
	return fmt.Sprintf("m-%s-%d", what, time.Now().UnixNano())
}

// diagnose logs what helps to tell where a message got lost.
func diagnose(t *testing.T) {
	t.Helper()
	run := func(name string, args ...string) {
		out, _ := exec.Command(name, args...).CombinedOutput()
		t.Logf("$ %s %s\n%s", name, strings.Join(args, " "), out)
	}
	run("docker", "ps", "-a", "--format", "{{.ID}} {{.Names}} {{.Status}} {{.Ports}} {{.Labels}}")
	for _, c := range []string{syslogName, logstashName} {
		if Inspect(t, c) == nil {
			continue
		}
		run("docker", "logs", "--tail", "50", c)
		if c == syslogName {
			run("docker", "exec", c, "syslog-ng-ctl", "stats", "-c", "/config/syslog-ng.ctl")
			run("docker", "exec", c, "cat", "/config/syslog-ng.conf")
		}
	}
	run("sh", "-c", "ss -ulpn | grep -E ':(514|102[5-8]) ' || true")
	run("sh", "-c", "sudo -n conntrack -L -p udp 2>/dev/null | grep -E 'dport=(514|102[5-8]) ' | head -20 || true")
}
