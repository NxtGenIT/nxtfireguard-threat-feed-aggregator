//go:build e2e

package e2e

import (
	"net/http"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

var allSyslog = Settings{SyslogEnabled: true, SyslogServices: Services{
	CiscoFTD: true, CiscoISE: true, OPNsense: true, PfSense: true, Suricata: true}}

var ftdOnly = Settings{SyslogEnabled: true, SyslogServices: Services{CiscoFTD: true}}

func newBackend(t *testing.T, s Settings) *Backend {
	return NewBackend(t, "agg-e2e", "e2e-secret-4711", "hb-e2e", s)
}

// waitRunning waits until the managed syslog container runs and returns it.
func waitRunning(t *testing.T, timeout time.Duration) *Container {
	t.Helper()
	var c *Container
	waitFor(t, timeout, syslogName+" running", func() bool {
		c = Inspect(t, syslogName)
		return c.Managed() && c.State.Running
	})
	return c
}

func ftdLine(m string) string {
	return rfc3164(113, "ftd01", "%FTD-1-430003:", "DeviceUUID: 1, AccessControlRuleAction: Block, SrcIP: 203.0.113.5, DstIP: 10.0.0.5, "+m)
}

// bodyRE is the request body syslog-ng builds: <PRI>ISO-time host program<sep>msg.
func bodyRE(pri, program, sep, msg string) *regexp.Regexp {
	return regexp.MustCompile(`^<` + pri + `>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3} \S+ ` +
		regexp.QuoteMeta(program+sep+msg) + `\n?$`)
}

// TestColdStart: the aggregator fetches its settings, starts syslog-ng with
// every relay, and only heartbeats once the container runs; each relay
// forwards to its collector route with the aggregator's credentials, and the
// OPNsense/pfSense relays drop everything but Suricata EVE JSON.
func TestColdStart(t *testing.T) {
	b := newBackend(t, allSyslog)
	a := StartAggregator(t, "", t.TempDir(), Env(b, t.TempDir()))

	waitFor(t, 30*time.Second, "settings sync with credentials", func() bool {
		for _, s := range b.Syncs() {
			if s.Header.Get("X_AUTH_KEY") == b.Secret && s.Header.Get("X_AGGREGATOR_NAME") == b.Name {
				return true
			}
		}
		return false
	})
	waitFor(t, 30*time.Second, "update stream", func() bool { open, _ := b.Streams(); return open == 1 })

	c := waitRunning(t, 3*time.Minute)
	ports := c.UDPPorts()
	slices.Sort(ports)
	if want := []string{"1025/udp", "1026/udp", "1027/udp", "1028/udp", "514/udp"}; !slices.Equal(ports, want) {
		t.Fatalf("published ports %v, want %v", ports, want)
	}

	waitFor(t, 30*time.Second, "first heartbeat", func() bool { return len(b.Heartbeats()) > 0 })
	hb := b.Heartbeats()[0]
	if !hb.At.After(c.State.StartedAt) {
		t.Fatalf("heartbeat at %s before syslog-ng started at %s", hb.At, c.State.StartedAt)
	}
	if hb.Path != "/ping/"+b.HBID || hb.Header.Get("apikey") != b.Secret {
		t.Fatalf("heartbeat %s with apikey %q", hb.Path, hb.Header.Get("apikey"))
	}

	eve := func(m string) string {
		return `{"timestamp":"2026-11-13T20:00:00.000000+0000","event_type":"alert","src_ip":"203.0.113.9","dest_ip":"10.0.0.9","proto":"TCP","alert":{"signature":"ET SCAN ` + m + `","severity":2}}`
	}
	cases := []struct {
		name, route string
		port        int
		line        func(m string) string
		body        func(m string) *regexp.Regexp
		dropped     []string // lines the relay must not forward
	}{
		{name: "ftd", route: "/firepower", port: 514, line: ftdLine,
			body: func(m string) *regexp.Regexp {
				return bodyRE("113", "%FTD-1-430003", ": ", "DeviceUUID: 1, AccessControlRuleAction: Block, SrcIP: 203.0.113.5, DstIP: 10.0.0.5, "+m)
			}},
		{name: "ise", route: "/ise", port: 1025,
			line: func(m string) string {
				return rfc3164(181, "ise01", "CISE_Failed_Attempts:", "0000123 1 0 2026-11-13 20:00:00.000 +01:00 5200 NOTICE Failed-Attempt: "+m)
			},
			body: func(m string) *regexp.Regexp {
				return bodyRE("181", "CISE_Failed_Attempts", ": ", "0000123 1 0 2026-11-13 20:00:00.000 +01:00 5200 NOTICE Failed-Attempt: "+m)
			}},
		{name: "opnsense", route: "/opnsense", port: 1026,
			line: func(m string) string { return rfc3164(14, "opn01", "suricata[4242]:", eve(m)) },
			body: func(m string) *regexp.Regexp { return bodyRE("14", "suricata", ": ", eve(m)) },
			dropped: []string{
				rfc3164(13, "opn01", "kernel:", "pf: blocked m-opnsense-kernel"),
				rfc3164(14, "opn01", "suricata[4242]:", "[1:2010937:3] ET SCAN plain-text copy m-opnsense-plain"),
			}},
		{name: "suricata", route: "/suricata", port: 1027,
			line: func(m string) string { return rfc3164(14, "ids01", "suricata[77]:", eve(m)) },
			// The Suricata relay has always been sent without the colon.
			body: func(m string) *regexp.Regexp { return bodyRE("14", "suricata", " ", eve(m)) }},
		{name: "pfsense", route: "/pfsense", port: 1028,
			line: func(m string) string { return rfc3164(14, "pf01", "suricata[999]:", eve(m)) },
			body: func(m string) *regexp.Regexp { return bodyRE("14", "suricata", ": ", eve(m)) },
			dropped: []string{
				rfc3164(29, "pf01", "nginx:", "GET /index.php m-pfsense-nginx"),
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := marker(tc.name)
			got := deliver(t, b, tc.port, m, append(slices.Clone(tc.dropped), tc.line(m))...)
			if got.Path != tc.route {
				t.Errorf("path %s, want %s", got.Path, tc.route)
			}
			if k := got.Header.Get("X-AUTH_KEY"); k != b.Secret {
				t.Errorf("X-AUTH_KEY %q", k)
			}
			if n := got.Header.Get("X-AGGREGATOR_NAME"); n != b.Name {
				t.Errorf("X-AGGREGATOR_NAME %q", n)
			}
			if re := tc.body(m); !re.MatchString(got.Body) {
				t.Errorf("body %q does not match %s", got.Body, re)
			}
			for _, d := range []string{"m-opnsense-kernel", "m-opnsense-plain", "m-pfsense-nginx"} {
				if strings.Contains(strings.Join(tc.dropped, "\n"), d) && len(b.Collected(d)) > 0 {
					t.Errorf("%s was forwarded, the relay should only pass Suricata EVE JSON", d)
				}
			}
		})
	}

	// docker runs the health check (syslog-ng-ctl stats) every 30s.
	waitFor(t, 75*time.Second, "docker health check to pass", func() bool {
		h := Inspect(t, syslogName).Health()
		if h == "unhealthy" {
			t.Fatal("syslog-ng health check fails")
		}
		return h == "healthy"
	})
	if l := a.LogLines("skipping heartbeat"); len(l) > 1 {
		t.Errorf("heartbeat skipped %d times after start: %v", len(l), l)
	}
}

// TestSettingsPushed: dashboard changes arrive over the update stream and the
// container is recreated only when its configuration changes.
func TestSettingsPushed(t *testing.T) {
	b := newBackend(t, ftdOnly)
	a := StartAggregator(t, "", t.TempDir(), Env(b, t.TempDir()))
	waitFor(t, 30*time.Second, "update stream", func() bool { open, _ := b.Streams(); return open == 1 })
	id := waitRunning(t, 3*time.Minute).ID
	mBefore := marker("before")
	deliver(t, b, 514, mBefore, ftdLine(mBefore))

	// The same settings again change nothing.
	b.Push(ftdOnly)
	never(t, 3*checkEvery, "container recreated for unchanged settings", func() bool {
		return Inspect(t, syslogName).ID != id
	})

	both := Settings{SyslogEnabled: true, SyslogServices: Services{CiscoFTD: true, CiscoISE: true}}
	b.Push(both)
	waitFor(t, time.Minute, "container recreated with the ISE port", func() bool {
		c := Inspect(t, syslogName)
		return c.Managed() && c.State.Running && c.ID != id && slices.Contains(c.UDPPorts(), "1025/udp")
	})
	m := marker("ise")
	got := deliver(t, b, 1025, m, rfc3164(181, "ise01", "CISE_Failed_Attempts:", m))
	if got.Path != "/ise" {
		t.Fatalf("ISE line went to %s", got.Path)
	}
	if len(a.LogLines("settings pushed")) < 2 {
		t.Fatal("pushes not logged as such")
	}

	b.Push(Settings{SyslogEnabled: false, SyslogServices: both.SyslogServices})
	waitFor(t, 30*time.Second, "syslog container removed", func() bool { return Inspect(t, syslogName) == nil })

	b.Push(ftdOnly)
	waitRunning(t, time.Minute)
}

// TestControllerOutage: while the controller is down the relays keep
// running and heartbeating; when it is back the aggregator reconnects and
// picks up what changed meanwhile without needing a push.
func TestControllerOutage(t *testing.T) {
	b := newBackend(t, ftdOnly)
	a := StartAggregator(t, "", t.TempDir(), Env(b, t.TempDir()))
	waitFor(t, 30*time.Second, "update stream", func() bool { open, _ := b.Streams(); return open == 1 })
	waitRunning(t, 3*time.Minute)
	waitFor(t, 30*time.Second, "heartbeat", func() bool { return len(b.Heartbeats()) > 0 })

	b.SetDown(true)
	b.SetSettings(Settings{SyslogEnabled: true, SyslogServices: Services{CiscoFTD: true, Suricata: true}})
	waitFor(t, 15*time.Second, "stream loss noticed", func() bool { return len(a.LogLines("update stream down")) > 0 })
	before := len(b.Heartbeats())
	waitFor(t, 5*checkEvery, "heartbeats during the outage", func() bool { return len(b.Heartbeats()) >= before+2 })
	mOutage := marker("outage")
	deliver(t, b, 514, mOutage, ftdLine(mOutage))

	b.SetDown(false)
	waitFor(t, 45*time.Second, "reconnect", func() bool { open, total := b.Streams(); return open == 1 && total >= 2 })
	waitFor(t, 30*time.Second, "settings changed during the outage applied", func() bool {
		c := Inspect(t, syslogName)
		return c.Managed() && c.State.Running && slices.Contains(c.UDPPorts(), "1027/udp")
	})
}

// TestRestartWithoutController: after a crash, the aggregator restarts from
// its saved settings while the controller is unreachable, keeps the running
// container, and heartbeats.
func TestRestartWithoutController(t *testing.T) {
	b := newBackend(t, ftdOnly)
	work, state := t.TempDir(), t.TempDir()
	a := StartAggregator(t, "", work, Env(b, state))
	id := waitRunning(t, 3*time.Minute).ID
	a.Kill()

	b.SetDown(true)
	hb := len(b.Heartbeats())
	a2 := StartAggregator(t, "", work, Env(b, state))
	waitFor(t, 15*time.Second, "start from saved settings", func() bool {
		return len(a2.LogLines("starting from saved settings")) > 0
	})
	waitFor(t, 5*checkEvery, "heartbeat without controller", func() bool { return len(b.Heartbeats()) > hb })
	if c := Inspect(t, syslogName); c.ID != id {
		t.Fatal("container recreated although its settings did not change")
	}
	mSaved := marker("saved")
	deliver(t, b, 514, mSaved, ftdLine(mSaved))
}

// TestContainerRecovery: a stopped container is started again at once; if
// it stops again soon after, the restart backs off for 30s, and no heartbeat
// is sent while it is down.
func TestContainerRecovery(t *testing.T) {
	b := newBackend(t, ftdOnly)
	a := StartAggregator(t, "", t.TempDir(), Env(b, t.TempDir()))
	first := waitRunning(t, 3*time.Minute)
	waitFor(t, 30*time.Second, "heartbeat", func() bool { return len(b.Heartbeats()) > 0 })

	docker(t, "stop", "-t", "1", syslogName)
	var second *Container
	waitFor(t, 30*time.Second, "restart after stop", func() bool {
		second = Inspect(t, syslogName)
		return second.State.Running && second.State.StartedAt.After(first.State.StartedAt)
	})
	if second.ID != first.ID {
		t.Fatalf("stopped container %.12s was replaced by %.12s, expected a restart of the same container", first.ID, second.ID)
	}

	docker(t, "stop", "-t", "1", syslogName)
	time.Sleep(checkEvery) // a heartbeat triggered just before the stop may still arrive
	hb := len(b.Heartbeats())
	never(t, 15*time.Second, "heartbeat while syslog-ng is down", func() bool {
		return len(b.Heartbeats()) > hb || Inspect(t, syslogName).State.Running
	})
	if len(a.LogLines("next attempt in")) == 0 {
		t.Error("backoff not reported")
	}
	waitFor(t, 45*time.Second, "restart after backoff", func() bool { return Inspect(t, syslogName).State.Running })
	waitFor(t, 5*checkEvery, "heartbeats resume", func() bool { return len(b.Heartbeats()) > hb })
	mRecovered := marker("recovered")
	deliver(t, b, 514, mRecovered, ftdLine(mRecovered))
}

// TestCollectorErrors: syslog-ng retries a collector that fails with 5xx or
// 429, and drops a message the collector rejects with 400 without holding
// up the ones after it (response-action(400 => drop)).
func TestCollectorErrors(t *testing.T) {
	b := newBackend(t, ftdOnly)
	StartAggregator(t, "", t.TempDir(), Env(b, t.TempDir()))
	waitRunning(t, 3*time.Minute)
	mWarmup := marker("warmup")
	deliver(t, b, 514, mWarmup, ftdLine(mWarmup))

	b.RespondWith(func(r Request, attempt int) int {
		switch {
		case strings.Contains(r.Body, "m-retry") && attempt <= 2:
			return http.StatusServiceUnavailable
		case strings.Contains(r.Body, "m-limited") && attempt == 1:
			return http.StatusTooManyRequests
		case strings.Contains(r.Body, "m-bad"):
			return http.StatusBadRequest
		}
		return http.StatusOK
	})
	accepted := func(m string) func() bool {
		return func() bool {
			for _, r := range b.Collected(m) {
				if r.Status == http.StatusOK {
					return true
				}
			}
			return false
		}
	}

	retry := marker("retry")
	sendSyslog(t, 514, ftdLine(retry))
	waitFor(t, time.Minute, "5xx retried until accepted", accepted(retry))
	if n := len(b.Collected(retry)); n != 3 {
		t.Errorf("message sent %d times, want 2 failures + 1 success", n)
	}

	limited := marker("limited")
	sendSyslog(t, 514, ftdLine(limited))
	waitFor(t, time.Minute, "429 retried until accepted", accepted(limited))

	bad, after := marker("bad"), marker("after")
	sendSyslog(t, 514, ftdLine(bad), ftdLine(after))
	waitFor(t, time.Minute, "message after a rejected one", accepted(after))
	if n := len(b.Collected(bad)); n != 1 {
		t.Errorf("rejected message sent %d times, want once (dropped)", n)
	}
}

// TestShutdown: SIGTERM removes the containers and exits cleanly.
func TestShutdown(t *testing.T) {
	b := newBackend(t, ftdOnly)
	a := StartAggregator(t, "", t.TempDir(), Env(b, t.TempDir()))
	waitRunning(t, 3*time.Minute)
	if err := a.Stop(syscall.SIGTERM, 40*time.Second); err != nil {
		t.Fatalf("exit after SIGTERM: %v", err)
	}
	if Inspect(t, syslogName) != nil {
		t.Fatal("container left after SIGTERM")
	}
	if len(a.LogLines("container removed")) == 0 {
		t.Error("removal not logged")
	}
}

// TestUnsafeSecret: a secret syslog-ng cannot carry is reported, no relay
// starts and no heartbeat claims the aggregator is fine.
func TestUnsafeSecret(t *testing.T) {
	b := NewBackend(t, "agg-e2e", `bad"secret`, "hb-e2e", ftdOnly)
	a := StartAggregator(t, "", t.TempDir(), Env(b, t.TempDir()))
	waitFor(t, 30*time.Second, "problem reported", func() bool {
		return len(a.LogLines("AUTH_SECRET contains a quote")) > 0
	})
	never(t, 4*checkEvery, "relay started or heartbeat sent", func() bool {
		return Inspect(t, syslogName) != nil || len(b.Heartbeats()) > 0
	})
}
