package render

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/config"
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/services"
)

var col = Collector{URL: "https://collector.example", Name: "agg-1"}

// normalize drops what syslog-ng and Logstash ignore (indentation, blank
// lines), so the goldens captured from the previous implementation compare.
func normalize(s string) string {
	brace := regexp.MustCompile(`(\S)\{$`)
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		out = append(out, brace.ReplaceAllString(l, "$1 {"))
	}
	return strings.Join(out, "\n") + "\n"
}

func toggles(mask int) services.Toggles {
	return services.Toggles{
		CiscoFTD: mask&1 != 0, CiscoISE: mask&2 != 0, OPNsense: mask&4 != 0,
		Suricata: mask&8 != 0, PfSense: mask&16 != 0,
	}
}

// The goldens are the old output for every combination of services, with the
// inline secret replaced by the environment reference, without the
// internal() sources (syslog-ng logs to docker logs instead), and with 400
// and 404 answered by "success" instead of "drop" (see Syslog).
func TestSyslogMatchesPreviousOutput(t *testing.T) {
	for mask := 0; mask < 32; mask++ {
		want, err := os.ReadFile(fmt.Sprintf("testdata/syslog-%02d.conf", mask))
		if err != nil {
			t.Fatal(err)
		}
		got := normalize(Syslog(col, services.Enabled(toggles(mask))))
		if got != string(want) {
			t.Errorf("mask %d:\n--- got\n%s\n--- want\n%s", mask, got, want)
		}
	}
}

func TestSyslogEscapesName(t *testing.T) {
	got := Syslog(Collector{URL: "https://c", Name: "a\"b`X`"}, services.Enabled(services.Toggles{CiscoFTD: true}))
	if !strings.Contains(got, `X-AGGREGATOR_NAME: a\"bX"`) {
		t.Fatalf("name not escaped:\n%s", got)
	}
}

func TestLogstashMatchesPreviousOutput(t *testing.T) {
	targets := []config.ESTarget{
		{URL: "http://es1:9200", User: "u1", Password: "p1"},
		{URL: "http://es2:9200", User: "", Password: "p2"},
		{URL: "http://es3:9200", User: "u3", Password: "p3"},
	}
	got, env, err := Logstash(col, targets)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile("testdata/logstash.conf")
	if normalize(got) != string(want) {
		t.Errorf("--- got\n%s\n--- want\n%s", normalize(got), want)
	}
	if len(env) != 2 || env["NFG_ES_PASS_0"] != "p1" || env["NFG_ES_PASS_1"] != "p3" {
		t.Errorf("env = %v", env)
	}
	for _, secret := range []string{"p1", "p2", "p3"} {
		if strings.Contains(got, `"`+secret+`"`) {
			t.Errorf("pipeline contains password %q", secret)
		}
	}
}

func TestLogstashNeedsATarget(t *testing.T) {
	if _, _, err := Logstash(col, []config.ESTarget{{URL: "http://es"}}); err == nil {
		t.Fatal("want error without a usable target")
	}
}

func TestLogstashRejectsQuotes(t *testing.T) {
	if _, _, err := Logstash(col, []config.ESTarget{{URL: `http://es"`, User: "u"}}); err == nil {
		t.Fatal("want error for a quote in the URL")
	}
}

func TestSyslogHasNoInternalSource(t *testing.T) {
	got := Syslog(col, services.Enabled(toggles(31)))
	if strings.Contains(got, "internal()") {
		t.Fatalf("syslog-ng's own messages must not be relayed to the collector:\n%s", got)
	}
}

func TestCheckSyslogSecret(t *testing.T) {
	for _, ok := range []config.Secret{"abc-DEF_123", "with space", "p@ss$word!"} {
		if err := CheckSyslogSecret(ok); err != nil {
			t.Errorf("%q: %v", ok.Reveal(), err)
		}
	}
	for _, bad := range []config.Secret{`a"b`, `a\b`, "a`b", "a\nb"} {
		err := CheckSyslogSecret(bad)
		if err == nil {
			t.Errorf("%q accepted", bad.Reveal())
			continue
		}
		if strings.Contains(err.Error(), bad.Reveal()) {
			t.Errorf("error leaks the secret: %v", err)
		}
	}
}
