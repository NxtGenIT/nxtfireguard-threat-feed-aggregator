package config

import (
	"encoding/json"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Debug                 bool
	AggregatorName        string
	SyslogEnabled         bool
	LogstashEnabled       bool
	AuthSecret            string
	HeartbeatIdentifier   string
	HeartbeatUrl          string
	NfgTfaControllerUrl   string
	NfgTfaControllerHost  string
	NfgThreatCollectorUrl string
	InsecureSkipVerifyTLS bool
	LogToLoki             bool
	LokiAddress           string
	WsKeepalivePeriod     time.Duration
	ElasticsearchTargets  []ElasticsearchTarget
}

func (c *Config) SetSyslogEnabled(v bool) {
	if c.SyslogEnabled != v {
		c.SyslogEnabled = v
		go handleSyslogChange(c)
	}
}

func (c *Config) SetLogstashEnabled(v bool) {
	if c.LogstashEnabled != v {
		c.LogstashEnabled = v
		go handleLogstashChange(c)
	}
}

func Load() *Config {
	debug, _ := strconv.ParseBool(getEnv("DEBUG", "false"))
	insecureSkipVerify, _ := strconv.ParseBool(getEnv("SKIP_VERIFY_TLS", "false"))
	logToLoki, _ := strconv.ParseBool(getEnv("LOG_TO_LOKI", "false"))

	cfg := &Config{
		Debug:                 debug,
		AggregatorName:        getEnv("AGGREGATOR_NAME", ""),
		AuthSecret:            getEnv("AUTH_SECRET", ""),
		HeartbeatIdentifier:   getEnv("HEARTBEAT_IDENTIFIER", ""),
		HeartbeatUrl:          getEnv("HEARTBEAT_URL", ""),
		NfgTfaControllerUrl:   getEnv("NFG_TFA_CONTROLLER_URL", "https://controller.collector.nxtfireguard.nxtgenit.de"),
		NfgTfaControllerHost:  getEnv("NFG_TFA_CONTROLLER_HOST", "controller.collector.nxtfireguard.nxtgenit.de"),
		NfgThreatCollectorUrl: getEnv("THREAT_LOG_COLLECTOR_URL", "https://threats.collector.nxtfireguard.nxtgenit.de"),
		InsecureSkipVerifyTLS: insecureSkipVerify,
		LogToLoki:             logToLoki,
		LokiAddress:           getEnv("LOKI_ADDRESS", "loki.nxtfireguard.de"),
		WsKeepalivePeriod:     30 * time.Second,
	}

	// Parse Elasticsearch targets
	esTargetsJSON := getEnv("ELASTICSEARCH_TARGETS", "[]")
	if err := json.Unmarshal([]byte(esTargetsJSON), &cfg.ElasticsearchTargets); err != nil {
		panic("failed to parse ELASTICSEARCH_TARGETS: " + err.Error())
	}

	return cfg
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
