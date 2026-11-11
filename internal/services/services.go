// Package services is the single list of syslog relays the aggregator can run.
// Everything that depends on it (syslog-ng config, published ports, the
// remote toggles) is derived from Table.
package services

// Toggles is the syslogServices object sent by the tfa-controller.
type Toggles struct {
	CiscoFTD bool `json:"syslogCiscoFtdEnabled"`
	CiscoISE bool `json:"syslogCiscoIseEnabled"`
	OPNsense bool `json:"syslogOpnsenseEnabled"`
	PfSense  bool `json:"syslogPfsenseEnabled"`
	Suricata bool `json:"syslogSuricataEnabled"`
}

// Service is one UDP syslog listener forwarded to a threat-collector route.
type Service struct {
	// ID names the syslog-ng objects (s_network_<ID>, d_http_<ID>).
	ID    string
	Label string
	Port  int
	// Route is the threat-collector path the messages are POSTed to.
	Route string
	// SuricataEVEOnly drops everything except Suricata EVE JSON. OPNsense and
	// pfSense forward every syslog line (kernel, nginx, the plain-text alert
	// copy), which the collector rejects.
	SuricataEVEOnly bool
	// ProgramColon puts ": " between $PROGRAM and $MSG in the body. The
	// Suricata relay has always been sent without it.
	ProgramColon bool
	// WithInternal adds syslog-ng's internal() source to this listener, as the
	// Suricata relay has always done.
	WithInternal bool
	Enabled      func(Toggles) bool
}

// Table is in the order the syslog-ng config and the port list are written.
var Table = []Service{
	{ID: "firepower", Label: "Cisco FTD", Port: 514, Route: "/firepower", ProgramColon: true,
		Enabled: func(t Toggles) bool { return t.CiscoFTD }},
	{ID: "ise", Label: "Cisco ISE", Port: 1025, Route: "/ise", ProgramColon: true,
		Enabled: func(t Toggles) bool { return t.CiscoISE }},
	{ID: "opnsense", Label: "OPNsense", Port: 1026, Route: "/opnsense", ProgramColon: true, SuricataEVEOnly: true,
		Enabled: func(t Toggles) bool { return t.OPNsense }},
	{ID: "suricata", Label: "Suricata", Port: 1027, Route: "/suricata", WithInternal: true,
		Enabled: func(t Toggles) bool { return t.Suricata }},
	{ID: "pfsense", Label: "pfSense", Port: 1028, Route: "/pfsense", ProgramColon: true, SuricataEVEOnly: true,
		Enabled: func(t Toggles) bool { return t.PfSense }},
}

// Enabled returns the services switched on in t, in table order.
func Enabled(t Toggles) []Service {
	var out []Service
	for _, s := range Table {
		if s.Enabled(t) {
			out = append(out, s)
		}
	}
	return out
}
