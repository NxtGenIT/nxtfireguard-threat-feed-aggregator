// Package config reads the aggregator's static settings from the environment.
// What runs (syslog relays, Logstash) is decided remotely; see package nfg.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

// Secret is a credential that never shows up in logs or dumps.
type Secret string

func (Secret) String() string               { return "[redacted]" }
func (Secret) GoString() string             { return `"[redacted]"` }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }
func (Secret) MarshalText() ([]byte, error) { return []byte("[redacted]"), nil }
func (s Secret) Reveal() string             { return string(s) }

// ESTarget is one T-Pot Elasticsearch the Logstash relay reads from.
type ESTarget struct {
	URL      string `json:"url"`
	User     string `json:"user"`
	Password Secret `json:"-"`
}

func (t *ESTarget) UnmarshalJSON(b []byte) error {
	var raw struct {
		URL  string `json:"url"`
		User string `json:"user"`
		Pass string `json:"pass"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*t = ESTarget{URL: raw.URL, User: raw.User, Password: Secret(raw.Pass)}
	return nil
}

type Config struct {
	Debug bool
	Name  string
	Key   Secret

	HeartbeatID  string
	HeartbeatURL string

	ControllerURL   string
	ControllerWSURL string
	CollectorURL    string
	SkipVerifyTLS   bool

	// StateDir holds the generated container configs and the last remote
	// settings, so a restart works while the controller is unreachable.
	StateDir string

	ESTargets []ESTarget
}

// Load reads the configuration through getenv. Warnings are non-fatal
// problems worth logging once the logger exists.
func Load(getenv func(string) (string, bool)) (Config, []string, error) {
	get := func(key, def string) string {
		if v, ok := getenv(key); ok {
			return strings.TrimSpace(v)
		}
		return def
	}
	var warnings []string
	boolean := func(key string) bool {
		v := get(key, "")
		if v == "" {
			return false
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s=%q is not a boolean, using false", key, v))
		}
		return b
	}

	c := Config{
		Debug:         boolean("DEBUG"),
		Name:          get("AGGREGATOR_NAME", ""),
		Key:           Secret(get("AUTH_SECRET", "")),
		HeartbeatID:   get("HEARTBEAT_IDENTIFIER", ""),
		HeartbeatURL:  strings.TrimRight(get("HEARTBEAT_URL", "https://heartbeat.nxtfireguard.de"), "/"),
		ControllerURL: strings.TrimRight(get("NFG_TFA_CONTROLLER_URL", "https://controller.collector.nxtfireguard.de"), "/"),
		CollectorURL:  strings.TrimRight(get("THREAT_LOG_COLLECTOR_URL", "https://threat.collector.nxtfireguard.de"), "/"),
		SkipVerifyTLS: boolean("SKIP_VERIFY_TLS"),
	}

	var errs []error
	if c.Name == "" {
		errs = append(errs, errors.New("AGGREGATOR_NAME is required"))
	}
	if c.Key == "" {
		errs = append(errs, errors.New("AUTH_SECRET is required"))
	}
	if c.HeartbeatID == "" {
		warnings = append(warnings, "HEARTBEAT_IDENTIFIER is empty, heartbeats are disabled")
	}
	for _, k := range []string{"LOG_TO_LOKI", "LOKI_ADDRESS"} {
		if _, ok := getenv(k); ok {
			warnings = append(warnings, k+" is ignored: logs go to stdout as JSON")
		}
	}

	ws, err := websocketURL(c.ControllerURL, get("NFG_TFA_CONTROLLER_HOST", ""))
	if err != nil {
		errs = append(errs, err)
	}
	c.ControllerWSURL = ws

	if raw := get("ELASTICSEARCH_TARGETS", ""); raw != "" {
		// .env files written for the old version wrap the JSON in single quotes.
		raw = strings.Trim(raw, "'")
		if err := json.Unmarshal([]byte(raw), &c.ESTargets); err != nil {
			errs = append(errs, fmt.Errorf("ELASTICSEARCH_TARGETS is not a JSON list of {url,user,pass}: %w", err))
		}
	}

	dir := get("NFG_STATE_DIR", "nfgtfa-state")
	abs, err := filepath.Abs(dir)
	if err != nil {
		errs = append(errs, fmt.Errorf("NFG_STATE_DIR: %w", err))
	}
	c.StateDir = abs

	return c, warnings, errors.Join(errs...)
}

// websocketURL derives the update stream from the controller URL. An explicit
// NFG_TFA_CONTROLLER_HOST (the old way to configure it) only replaces the host.
func websocketURL(controller, host string) (string, error) {
	u, err := url.Parse(controller)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("NFG_TFA_CONTROLLER_URL %q is not an absolute URL", controller)
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("NFG_TFA_CONTROLLER_URL %q must be http or https", controller)
	}
	if host != "" {
		u.Host = host
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/sync/ws/updates"
	return u.String(), nil
}
