package models

type SyslogServices struct {
	SyslogCiscoFtdEnabled bool `json:"syslogCiscoFtdEnabled"`
	SyslogCiscoIseEnabled bool `json:"syslogCiscoIseEnabled"`
	SyslogOpnsenseEnabled bool `json:"syslogOpnsenseEnabled"`
	SyslogSuricataEnabled bool `json:"syslogSuricataEnabled"`
}
