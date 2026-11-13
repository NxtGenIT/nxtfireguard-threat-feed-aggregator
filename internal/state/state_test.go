package state

import (
	"os"
	"testing"
)

func TestWriteFileReportsChanges(t *testing.T) {
	d := Dir(t.TempDir())
	for i, tc := range []struct {
		data    string
		changed bool
	}{{"a", true}, {"a", false}, {"b", true}} {
		changed, err := d.WriteFile("sub/f.conf", []byte(tc.data))
		if err != nil || changed != tc.changed {
			t.Fatalf("%d: changed=%v err=%v", i, changed, err)
		}
	}
	info, err := os.Stat(d.Path("sub/f.conf"))
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v err %v", info.Mode(), err)
	}
	if info, _ := os.Stat(d.Path("sub")); info.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v", info.Mode())
	}
}

func TestJSONRoundTrip(t *testing.T) {
	d := Dir(t.TempDir())
	var v map[string]int
	if ok, err := d.LoadJSON("x.json", &v); ok || err != nil {
		t.Fatalf("missing file: ok=%v err=%v", ok, err)
	}
	if err := d.SaveJSON("x.json", map[string]int{"a": 1}); err != nil {
		t.Fatal(err)
	}
	if ok, err := d.LoadJSON("x.json", &v); !ok || err != nil || v["a"] != 1 {
		t.Fatalf("ok=%v err=%v v=%v", ok, err, v)
	}
}
