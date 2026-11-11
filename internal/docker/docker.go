// Package docker runs containers through the docker CLI, which is the only
// thing the aggregator requires on the host (Linux, macOS or Windows).
package docker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/config"
)

const (
	ManagedLabel = "nfg.managed"
	HashLabel    = "nfg.spec-hash"
)

type Mount struct {
	Source, Target string
	ReadOnly       bool
}

// Spec describes one managed container. Two specs with the same Hash produce
// the same container, so a running container is only recreated when it differs.
type Spec struct {
	Name    string
	Image   string
	Ports   []string // docker -p syntax, e.g. "514:514/udp"
	Mounts  []Mount
	Network string
	Env     map[string]string
	// Secrets are handed to the container by name only (-e NAME), so the
	// values come from the docker CLI's environment and stay out of argv.
	Secrets     map[string]config.Secret
	HealthCmd   []string
	ContentHash string // hash of the mounted files' contents
}

func (s Spec) Hash() string {
	h := sha256.New()
	secretNames := sortedKeys(s.Secrets)
	secretDigests := make([]string, 0, len(secretNames))
	for _, k := range secretNames {
		d := sha256.Sum256([]byte(s.Secrets[k].Reveal()))
		secretDigests = append(secretDigests, k+"="+hex.EncodeToString(d[:8]))
	}
	_ = json.NewEncoder(h).Encode(struct {
		Spec
		Secrets []string
	}{Spec: Spec{Name: s.Name, Image: s.Image, Ports: s.Ports, Mounts: s.Mounts, Network: s.Network,
		Env: s.Env, HealthCmd: s.HealthCmd, ContentHash: s.ContentHash}, Secrets: secretDigests})
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// RunArgs are the docker arguments that create the container.
func (s Spec) RunArgs() []string {
	args := []string{"run", "-d", "--name", s.Name,
		"--restart", "unless-stopped",
		"--label", ManagedLabel + "=true",
		"--label", HashLabel + "=" + s.Hash(),
		"--log-driver", "json-file", "--log-opt", "max-size=10m", "--log-opt", "max-file=3",
	}
	for _, p := range s.Ports {
		args = append(args, "-p", p)
	}
	for _, m := range s.Mounts {
		v := "type=bind,source=" + m.Source + ",target=" + m.Target
		if m.ReadOnly {
			v += ",readonly"
		}
		args = append(args, "--mount", v)
	}
	if s.Network != "" {
		args = append(args, "--network", s.Network)
	}
	for _, k := range sortedKeys(s.Env) {
		args = append(args, "-e", k+"="+s.Env[k])
	}
	for _, k := range sortedKeys(s.Secrets) {
		args = append(args, "-e", k)
	}
	if len(s.HealthCmd) > 0 {
		cmd, _ := json.Marshal(append([]string{"CMD"}, s.HealthCmd...))
		args = append(args, "--health-cmd", string(cmd),
			"--health-interval", "30s", "--health-timeout", "10s", "--health-retries", "3")
	}
	return append(args, s.Image)
}

// Container is the observed state of a managed container.
type Container struct {
	Name    string
	Running bool
	// Health is "", "starting", "healthy" or "unhealthy".
	Health string
	Hash   string
}

// Runtime is what the reconciler needs from docker.
type Runtime interface {
	List(ctx context.Context) ([]Container, error)
	Run(ctx context.Context, s Spec) error
	Remove(ctx context.Context, name string) error
	Logs(ctx context.Context, name string, tail int) (string, error)
	NetworkExists(ctx context.Context, name string) (bool, error)
}

// CLI implements Runtime with the docker binary on PATH.
type CLI struct{}

func (CLI) run(ctx context.Context, extraEnv []string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("docker %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func (c CLI) List(ctx context.Context) ([]Container, error) {
	out, err := c.run(ctx, nil, "ps", "-a", "--no-trunc",
		"--filter", "label="+ManagedLabel+"=true",
		"--format", `{{.Names}}	{{.State}}	{{.Status}}	{{.Label "`+HashLabel+`"}}`)
	if err != nil {
		return nil, err
	}
	return parsePS(out), nil
}

func parsePS(out []byte) []Container {
	var cs []Container
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) != 4 {
			continue
		}
		c := Container{Name: f[0], Running: f[1] == "running", Hash: f[3]}
		switch {
		case strings.Contains(f[2], "(healthy)"):
			c.Health = "healthy"
		case strings.Contains(f[2], "(unhealthy)"):
			c.Health = "unhealthy"
		case strings.Contains(f[2], "(health: starting)"):
			c.Health = "starting"
		}
		cs = append(cs, c)
	}
	return cs
}

func (c CLI) Run(ctx context.Context, s Spec) error {
	env := make([]string, 0, len(s.Secrets))
	for k, v := range s.Secrets {
		env = append(env, k+"="+v.Reveal())
	}
	_, err := c.run(ctx, env, s.RunArgs()...)
	return err
}

func (c CLI) Remove(ctx context.Context, name string) error {
	_, err := c.run(ctx, nil, "rm", "-f", name)
	if err != nil && strings.Contains(err.Error(), "No such container") {
		return nil
	}
	return err
}

func (c CLI) Logs(ctx context.Context, name string, tail int) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "logs", "--tail", fmt.Sprint(tail), name)
	// Logstash writes to both streams.
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker logs %s: %w", name, err)
	}
	return string(out), nil
}

func (c CLI) NetworkExists(ctx context.Context, name string) (bool, error) {
	_, err := c.run(ctx, nil, "network", "inspect", "--format", "{{.Name}}", name)
	if err == nil {
		return true, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return false, nil
	}
	return false, err
}

// RemoveLegacyNetworks deletes the per-run compose networks (nfgtfa-*_default)
// that versions before the reconciler left behind.
func (c CLI) RemoveLegacyNetworks(ctx context.Context) []string {
	out, err := c.run(ctx, nil, "network", "ls", "--format", "{{.Name}}")
	if err != nil {
		return nil
	}
	var removed []string
	for _, n := range strings.Fields(string(out)) {
		if strings.HasPrefix(n, "nfgtfa-") && strings.HasSuffix(n, "_default") {
			if _, err := c.run(ctx, nil, "network", "rm", n); err == nil {
				removed = append(removed, n)
			}
		}
	}
	return removed
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
