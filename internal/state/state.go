// Package state keeps the aggregator's files in one directory that survives
// restarts: the generated container configs and the last remote settings.
package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type Dir string

func (d Dir) Path(elem ...string) string {
	return filepath.Join(append([]string{string(d)}, elem...)...)
}

// WriteFile atomically replaces name with data unless it already holds it, and
// reports whether it changed. Files are 0644 because the containers read them
// as their own user; nothing written here contains a secret.
func (d Dir) WriteFile(name string, data []byte) (bool, error) {
	p := d.Path(name)
	if old, err := os.ReadFile(p); err == nil && bytes.Equal(old, data) {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	return true, os.Rename(tmp.Name(), p)
}

// SaveJSON stores v as name.
func (d Dir) SaveJSON(name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = d.WriteFile(name, b)
	return err
}

// LoadJSON reads name into v; ok is false if the file does not exist.
func (d Dir) LoadJSON(name string, v any) (ok bool, err error) {
	b, err := os.ReadFile(d.Path(name))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(b, v)
}

// SettingsFile is where the last remote settings are kept.
const SettingsFile = "settings.json"
