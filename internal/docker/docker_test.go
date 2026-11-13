package docker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/config"
)

func spec() Spec {
	return Spec{
		Name: "nfg-syslog", Image: "img:1",
		Ports:       []string{"514:514/udp"},
		Mounts:      []Mount{{Source: "/state/a.conf", Target: "/config/a.conf", ReadOnly: true}},
		Network:     "net",
		Env:         map[string]string{"TZ": "Europe/Berlin", "PUID": "1000"},
		Secrets:     map[string]config.Secret{"NFG_AUTH_KEY": "topsecret"},
		HealthCmd:   []string{"curl", "-f", "http://localhost"},
		ContentHash: "abc",
	}
}

func TestRunArgs(t *testing.T) {
	args := strings.Join(spec().RunArgs(), " ")
	for _, want := range []string{
		"run -d --name nfg-syslog --restart unless-stopped",
		"--label nfg.managed=true --label nfg.spec-hash=" + spec().Hash(),
		"--log-driver json-file --log-opt max-size=10m --log-opt max-file=3",
		"-p 514:514/udp",
		"--mount type=bind,source=/state/a.conf,target=/config/a.conf,readonly",
		"--network net",
		"-e PUID=1000 -e TZ=Europe/Berlin -e NFG_AUTH_KEY ",
		`--health-cmd curl -f http://localhost --health-interval`,
	} {
		if !strings.Contains(args, want) {
			t.Errorf("args missing %q:\n%s", want, args)
		}
	}
	if !strings.HasSuffix(args, " img:1") {
		t.Errorf("image must be last: %s", args)
	}
	if strings.Contains(args, "topsecret") {
		t.Errorf("secret value in argv: %s", args)
	}
}

func TestHash(t *testing.T) {
	a := spec()
	if a.Hash() != spec().Hash() {
		t.Fatal("hash not stable")
	}
	changes := map[string]func(*Spec){
		"content": func(s *Spec) { s.ContentHash = "def" },
		"secret":  func(s *Spec) { s.Secrets = map[string]config.Secret{"NFG_AUTH_KEY": "rotated"} },
		"port":    func(s *Spec) { s.Ports = append(s.Ports, "1025:1025/udp") },
		"image":   func(s *Spec) { s.Image = "img:2" },
	}
	for name, change := range changes {
		b := spec()
		change(&b)
		if b.Hash() == a.Hash() {
			t.Errorf("%s change does not change the hash", name)
		}
	}
}

func TestParsePS(t *testing.T) {
	out := "nfg-logstash\trunning\tUp 3 minutes (healthy)\th1\n" +
		"nfg-syslog\texited\tExited (1) 2 seconds ago\th2\n" +
		"x\trunning\tUp 1 second (health: starting)\th3\n" +
		"y\trunning\tUp 1 hour (unhealthy)\t\n" +
		"garbage\n"
	got := parsePS([]byte(out))
	want := []Container{
		{Name: "nfg-logstash", Running: true, Health: "healthy", Hash: "h1"},
		{Name: "nfg-syslog", Running: false, Hash: "h2"},
		{Name: "x", Running: true, Health: "starting", Hash: "h3"},
		{Name: "y", Running: true, Health: "unhealthy"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestMountPathsAreCSVQuoted(t *testing.T) {
	s := spec()
	s.Mounts = []Mount{{Source: `/Users/a,b/"x"/c.conf`, Target: "/config/c.conf"}}
	args := strings.Join(s.RunArgs(), " ")
	want := `--mount type=bind,"source=/Users/a,b/""x""/c.conf",target=/config/c.conf `
	if !strings.Contains(args, want) {
		t.Fatalf("args missing %q:\n%s", want, args)
	}
}

// fakeDocker writes a shell script standing in for the docker binary.
func fakeDocker(t *testing.T, script string) CLI {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell script stand-in")
	}
	p := filepath.Join(t.TempDir(), "docker")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return CLI{Binary: p}
}

func TestNetworkExists(t *testing.T) {
	ctx := context.Background()
	missing := fakeDocker(t, `echo "Error response from daemon: network tpotce_nginx_local not found" >&2; exit 1`)
	if ok, err := missing.NetworkExists(ctx, "tpotce_nginx_local"); ok || err != nil {
		t.Errorf("missing network: %v, %v", ok, err)
	}
	down := fakeDocker(t, `echo "Cannot connect to the Docker daemon at unix:///var/run/docker.sock" >&2; exit 1`)
	if _, err := down.NetworkExists(ctx, "x"); err == nil {
		t.Error("a daemon that is down must be an error, not a missing network")
	}
	there := fakeDocker(t, `echo x`)
	if ok, err := there.NetworkExists(ctx, "x"); !ok || err != nil {
		t.Errorf("existing network: %v, %v", ok, err)
	}
}

func TestCallsTimeOut(t *testing.T) {
	c := fakeDocker(t, `exec sleep 30`)
	c.Timeout = 100 * time.Millisecond
	start := time.Now()
	_, err := c.List(context.Background())
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("took %s", d)
	}
	if _, err := c.Logs(context.Background(), "x", 10); !errors.Is(err, ErrTimeout) {
		t.Fatalf("logs err = %v, want ErrTimeout", err)
	}
}

func TestRemoveLegacyNetworksReportsFailures(t *testing.T) {
	c := fakeDocker(t, `case "$2" in
ls) printf 'bridge\nnfgtfa-1_default\nnfgtfa-2_default\ntpotce_nginx_local\n';;
rm) [ "$3" = nfgtfa-1_default ] && exit 0; echo "network $3 has active endpoints" >&2; exit 1;;
esac`)
	removed, err := c.RemoveLegacyNetworks(context.Background())
	if len(removed) != 1 || removed[0] != "nfgtfa-1_default" || err == nil || !strings.Contains(err.Error(), "active endpoints") {
		t.Fatalf("removed %v, err %v", removed, err)
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"syslog-ng-ctl":                 "syslog-ng-ctl",
		"http://localhost:9600/_node/x": "http://localhost:9600/_node/x",
		"a b":                           "'a b'",
		"it's":                          `'it'"'"'s'`,
		"":                              "''",
		"$(rm -rf /)":                   "'$(rm -rf /)'",
	} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}
