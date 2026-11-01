package models

type SyslogServices struct {
	SyslogCiscoFtdEnabled bool `json:"syslogCiscoFtdEnabled"`
	SyslogCiscoIseEnabled bool `json:"syslogCiscoIseEnabled"`
	SyslogOpnsenseEnabled bool `json:"syslogOpnsenseEnabled"`
	SyslogPfsenseEnabled  bool `json:"syslogPfsenseEnabled"`
	SyslogSuricataEnabled bool `json:"syslogSuricataEnabled"`
}
