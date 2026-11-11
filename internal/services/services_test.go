package services

import "testing"

func TestTableIsConsistent(t *testing.T) {
	ports, ids := map[int]bool{}, map[string]bool{}
	for _, s := range Table {
		if ports[s.Port] || ids[s.ID] {
			t.Errorf("duplicate port or id in %+v", s)
		}
		ports[s.Port], ids[s.ID] = true, true
	}
}

func TestEnabledEachToggle(t *testing.T) {
	cases := map[string]Toggles{
		"firepower": {CiscoFTD: true}, "ise": {CiscoISE: true}, "opnsense": {OPNsense: true},
		"suricata": {Suricata: true}, "pfsense": {PfSense: true},
	}
	for id, tg := range cases {
		got := Enabled(tg)
		if len(got) != 1 || got[0].ID != id {
			t.Errorf("%s: got %+v", id, got)
		}
	}
	all := Enabled(Toggles{true, true, true, true, true})
	if len(all) != len(Table) {
		t.Errorf("all enabled: %d services", len(all))
	}
}
