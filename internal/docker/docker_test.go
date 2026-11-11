package docker

import (
	"strings"
	"testing"

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
		`--health-cmd ["CMD","curl","-f","http://localhost"]`,
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
