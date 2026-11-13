//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	tpotNetwork = "tpotce_nginx_local"
	esName      = "nfg-e2e-elasticsearch"
	esImage     = "docker.elastic.co/elasticsearch/elasticsearch:8.14.2"
)

// TestTPot: the Logstash relay needs T-Pot's network. Until it exists the
// aggregator reports that and does not heartbeat; once T-Pot (here: its
// network and an Elasticsearch on it) is up, Logstash starts on that network
// and forwards new T-Pot documents to /t-pot.
func TestTPot(t *testing.T) {
	cleanTPot := func() {
		_ = exec.Command("docker", "rm", "-f", esName, logstashName).Run()
		_ = exec.Command("docker", "network", "rm", tpotNetwork).Run()
	}
	cleanTPot()
	t.Cleanup(cleanTPot)

	b := newBackend(t, Settings{LogstashEnabled: true})
	env := Env(b, t.TempDir())
	env["ELASTICSEARCH_TARGETS"] = fmt.Sprintf(`[{"url":"http://%s:9200","user":"elastic","pass":"e2e-es-pass"}]`, esName)
	a := StartAggregator(t, "", t.TempDir(), env)

	waitFor(t, 30*time.Second, "missing T-Pot network reported", func() bool {
		return len(a.LogLines("is T-Pot running?")) > 0
	})
	never(t, 3*checkEvery, "heartbeat without the Logstash relay", func() bool { return len(b.Heartbeats()) > 0 })

	// "T-Pot" comes up: its network and Elasticsearch.
	docker(t, "network", "create", tpotNetwork)
	docker(t, "run", "-d", "--name", esName, "--network", tpotNetwork, "-p", "127.0.0.1::9200",
		"-e", "discovery.type=single-node", "-e", "xpack.security.enabled=false",
		"-e", "ES_JAVA_OPTS=-Xms512m -Xmx512m", esImage)
	// Bounded, so a stalled Elasticsearch cannot hang a waitFor callback.
	client := &http.Client{Timeout: 5 * time.Second}
	es := "http://" + docker(t, "port", esName, "9200/tcp")
	if i := strings.Index(es, "\n"); i > 0 {
		es = es[:i]
	}
	waitFor(t, 3*time.Minute, "Elasticsearch", func() bool {
		resp, err := client.Get(es + "/_cluster/health?wait_for_status=yellow&timeout=1s")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})

	// The failed start backs off 30s before the next attempt.
	var ls *Container
	waitFor(t, 4*time.Minute, "Logstash on the T-Pot network", func() bool {
		ls = Inspect(t, logstashName)
		return ls.Managed() && ls.State.Running
	})
	if _, ok := ls.NetworkSettings.Networks[tpotNetwork]; !ok {
		t.Fatalf("Logstash not on %s: %v", tpotNetwork, ls.NetworkSettings.Networks)
	}

	// Logstash polls every 2s for documents of the last 2s, so keep writing
	// fresh ones until one arrives.
	m := marker("tpot")
	index := es + "/logstash-" + time.Now().UTC().Format("2006.01.02") + "/_doc?refresh=true"
	var got []Request
	waitFor(t, 4*time.Minute, "T-Pot event at the collector", func() bool {
		doc, _ := json.Marshal(map[string]any{
			"@timestamp": time.Now().UTC().Format(time.RFC3339Nano),
			"type":       "Cowrie", "eventid": "cowrie.login.failed",
			"src_ip": "203.0.113.77", "t-pot_hostname": "tpot-e2e", "message": m,
		})
		resp, err := client.Post(index, "application/json", bytes.NewReader(doc))
		if err == nil {
			resp.Body.Close()
		}
		got = b.Collected(m)
		return len(got) > 0
	})
	r := got[0]
	if r.Path != "/t-pot" {
		t.Errorf("path %s, want /t-pot", r.Path)
	}
	if r.Header.Get("X-AUTH_KEY") != b.Secret || r.Header.Get("X-AGGREGATOR_NAME") != b.Name {
		t.Errorf("credentials %q / %q", r.Header.Get("X-AUTH_KEY"), r.Header.Get("X-AGGREGATOR_NAME"))
	}
	var ev map[string]any
	if err := json.Unmarshal([]byte(r.Body), &ev); err != nil {
		t.Fatalf("body is not JSON: %v\n%s", err, r.Body)
	}
	if ev["src_ip"] != "203.0.113.77" || ev["t-pot_hostname"] != "tpot-e2e" {
		t.Errorf("event fields lost: %s", r.Body)
	}
	waitFor(t, 30*time.Second, "heartbeat with Logstash running", func() bool { return len(b.Heartbeats()) > 0 })
}
