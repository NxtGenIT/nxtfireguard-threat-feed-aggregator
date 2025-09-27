package config

type UpdatedConfig struct {
	Name            string `json:"name"`
	SyslogEnabled   bool   `json:"syslogEnabled"`
	LogstashEnabled bool   `json:"logstashEnabled"`
}

type ConfigResponse struct {
	Config UpdatedConfig `json:"config"`
}

type ElasticsearchTarget struct {
	URL      string `json:"url"`
	User     string `json:"user,omitempty"`
	Password string `json:"pass,omitempty"`
}
