package reconcile

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/config"
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/docker"
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/nfg"
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/render"
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/services"
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/state"
)

const (
	SyslogName   = "nfg-syslog"
	LogstashName = "nfg-logstash"

	SyslogImage   = "linuxserver/syslog-ng:4.10.2"
	LogstashImage = "docker.elastic.co/logstash/logstash:8.14.2"

	// TPotNetwork is created by T-Pot; Logstash reaches its Elasticsearch there.
	TPotNetwork = "tpotce_nginx_local"
)

//go:embed logstash.yml
var logstashYML []byte

// unit is one container the settings ask for.
type unit struct {
	spec docker.Spec
	// files are written to the state dir (relative path → content) before the
	// container is created.
	files map[string][]byte
	// checkLogs marks a container whose recent logs reveal a broken upstream.
	checkLogs bool
	// err explains why the unit cannot be started from the current settings.
	err error
}

func desired(cfg config.Config, dir state.Dir, s nfg.Settings) []unit {
	col := render.Collector{URL: cfg.CollectorURL, Name: cfg.Name}
	key := map[string]config.Secret{render.AuthKeyEnv: cfg.Key}
	var units []unit

	if enabled := services.Enabled(s.SyslogServices); s.SyslogEnabled && len(enabled) > 0 {
		conf := []byte(render.Syslog(col, enabled))
		u := unit{
			files: map[string][]byte{"syslog-ng/syslog-ng.conf": conf},
			spec: docker.Spec{
				Name:    SyslogName,
				Image:   SyslogImage,
				Env:     map[string]string{"PUID": "1000", "PGID": "1000", "TZ": "Europe/Berlin"},
				Secrets: key,
				Mounts:  []docker.Mount{{Source: dir.Path("syslog-ng", "syslog-ng.conf"), Target: "/config/syslog-ng.conf"}},
			},
		}
		for _, svc := range enabled {
			u.spec.Ports = append(u.spec.Ports, fmt.Sprintf("%d:%d/udp", svc.Port, svc.Port))
		}
		units = append(units, u)
	}

	if s.LogstashEnabled {
		u := unit{checkLogs: true, spec: docker.Spec{
			Name:      LogstashName,
			Image:     LogstashImage,
			Network:   TPotNetwork,
			HealthCmd: []string{"curl", "-f", "http://localhost:9600/_node/stats"},
			Mounts: []docker.Mount{
				{Source: dir.Path("logstash", "logstash.conf"), Target: "/usr/share/logstash/pipeline/logstash.conf"},
				{Source: dir.Path("logstash", "logstash.yml"), Target: "/usr/share/logstash/config/logstash.yml"},
			},
		}}
		pipeline, passwords, err := render.Logstash(col, cfg.ESTargets)
		if err != nil {
			u.err = err
		}
		secrets := map[string]config.Secret{render.AuthKeyEnv: cfg.Key}
		for k, v := range passwords {
			secrets[k] = v
		}
		u.spec.Secrets = secrets
		u.files = map[string][]byte{"logstash/logstash.conf": []byte(pipeline), "logstash/logstash.yml": logstashYML}
		units = append(units, u)
	}

	for i := range units {
		units[i].spec.ContentHash = contentHash(units[i].files)
	}
	return units
}

func contentHash(files map[string][]byte) string {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		fmt.Fprintf(h, "%s\x00%d\x00", n, len(files[n]))
		h.Write(files[n])
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
