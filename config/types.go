package config

import "github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/models"

type UpdatedConfig struct {
	Name            string                `json:"name"`
	SyslogEnabled   bool                  `json:"syslogEnabled"`
	SyslogServices  models.SyslogServices `json:"syslogServices"`
	LogstashEnabled bool                  `json:"logstashEnabled"`
}

type ConfigResponse struct {
	Config UpdatedConfig `json:"config"`
}

type ElasticsearchTarget struct {
	URL      string `json:"url"`
	User     string `json:"user,omitempty"`
	Password string `json:"pass,omitempty"`
}

type RemoteConfig struct {
	SyslogEnabled   bool                  `json:"syslogEnabled"`
	LogstashEnabled bool                  `json:"logstashEnabled"`
	SyslogServices  models.SyslogServices `json:"syslogServices"`
}
