// Package render writes the syslog-ng and Logstash configurations.
//
// Credentials are never written into the files: both tools expand environment
// variables in their config, and the container gets the values from the
// aggregator's environment (docker run -e NAME, without a value).
package render

import (
	"fmt"
	"strings"

	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/config"
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/services"
)

// AuthKeyEnv carries AUTH_SECRET into the containers.
const AuthKeyEnv = "NFG_AUTH_KEY"

// Collector identifies the aggregator to the threat collector.
type Collector struct {
	URL  string
	Name string
}

// Syslog returns the syslog-ng.conf for the enabled services.
//
// There is no internal() source: the image starts syslog-ng with --stderr,
// so its own messages (startup, errors, stats) end up in `docker logs
// nfg-syslog`. Earlier versions fed them into the Suricata relay, which sent
// syslog-ng's complaints about a failing collector to that same collector.
func Syslog(c Collector, enabled []services.Service) string {
	var b strings.Builder
	b.WriteString("@version: 4.7\n@include \"scl.conf\"\n")

	for _, s := range enabled {
		fmt.Fprintf(&b, "\nsource s_network_%s {\n", s.ID)
		fmt.Fprintf(&b, "\tsyslog(transport(\"udp\") port(%d));\n};\n", s.Port)
	}

	for _, s := range enabled {
		if s.SuricataEVEOnly {
			b.WriteString("\nfilter f_suricata_eve {\n\tprogram(\"suricata\") and message(\"^\\\\s*\\\\{\");\n};\n")
			break
		}
	}

	for _, s := range enabled {
		sep := " "
		if s.ProgramColon {
			sep = ": "
		}
		// `NAME` is syslog-ng's environment variable reference; it is
		// substituted before the string literal is parsed.
		fmt.Fprintf(&b, `
destination d_http_%s {
	http(
		url("%s%s")
		method("POST")
		msg_data_in_header(no)
		headers("X-AUTH_KEY: `+"`%s`"+`", "X-AGGREGATOR_NAME: %s")
		body("<$PRI>$YEAR-$MONTH-${DAY}T$HOUR:$MIN:$SEC.$MSEC $HOST $PROGRAM%s$MSG")
		response-action(400 => drop, 404 => drop)
	);
};
`, s.ID, syslogString(c.URL), s.Route, AuthKeyEnv, syslogString(c.Name), sep)
	}

	for _, s := range enabled {
		fmt.Fprintf(&b, "\nlog {\n\tsource(s_network_%s);\n", s.ID)
		if s.SuricataEVEOnly {
			b.WriteString("\tfilter(f_suricata_eve);\n")
		}
		fmt.Fprintf(&b, "\tdestination(d_http_%s);\n};\n", s.ID)
	}
	return b.String()
}

// Logstash returns the pipeline that copies new T-Pot documents to the
// collector, plus the environment variables it references. Targets without a
// URL or user are skipped; an error means nothing is left to read from.
func Logstash(c Collector, targets []config.ESTarget) (pipeline string, env map[string]config.Secret, err error) {
	env = map[string]config.Secret{}
	var inputs []string
	for _, t := range targets {
		if t.URL == "" || t.User == "" {
			continue
		}
		if err := plainLogstashValue(t.URL, t.User); err != nil {
			return "", nil, err
		}
		passEnv := fmt.Sprintf("NFG_ES_PASS_%d", len(inputs))
		env[passEnv] = t.Password
		// The query and schedule poll every 2s for documents of the last 2s,
		// which is what the collector has always received.
		inputs = append(inputs, fmt.Sprintf(`input {
	elasticsearch {
		hosts => "%s"
		user => "%s"
		password => "${%s}"
		index => "logstash-*"
		query => '{ "query": { "range": { "@timestamp": { "gt": "now-2s" } } } }'
		schedule => "*/2 * * * * *"
		docinfo => true
	}
}
`, t.URL, t.User, passEnv))
	}
	if len(inputs) == 0 {
		return "", nil, fmt.Errorf("ELASTICSEARCH_TARGETS has no entry with url and user")
	}

	if err := plainLogstashValue(c.URL, c.Name); err != nil {
		return "", nil, err
	}
	output := fmt.Sprintf(`output {
	http {
		url => "%s/t-pot"
		http_method => "post"
		format => "json"
		headers => {
			"X-AUTH_KEY" => "${%s}"
			"X-AGGREGATOR_NAME" => "%s"
		}
	}
}
`, c.URL, AuthKeyEnv, c.Name)

	return strings.Join(inputs, "\n") + "\n" + output, env, nil
}

// CheckSyslogSecret reports whether secret can be referenced from the
// syslog-ng config. syslog-ng substitutes `NAME` before it parses the string
// literal around it, so a quote, a backslash or a line break in the value
// would end or corrupt the literal.
func CheckSyslogSecret(secret config.Secret) error {
	if strings.ContainsAny(secret.Reveal(), "\"\\`\r\n") {
		return fmt.Errorf("AUTH_SECRET contains a quote, backslash, backtick or line break, which the syslog-ng config cannot carry")
	}
	return nil
}

func syslogString(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "").Replace(s)
}

// Logstash does not process escapes in strings unless config.support_escapes
// is set, so a quote cannot be written safely.
func plainLogstashValue(values ...string) error {
	for _, v := range values {
		if strings.ContainsAny(v, `"\`) {
			return fmt.Errorf("value %q contains a quote or backslash, which Logstash cannot represent", v)
		}
	}
	return nil
}
