// Package reconcile makes the managed containers match the remote settings.
package reconcile

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/config"
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/docker"
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/nfg"
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/state"
	"go.uber.org/zap"
)

const (
	firstBackoff = 30 * time.Second
	maxBackoff   = 10 * time.Minute
	logTail      = 100
	// Logstash logs this when a T-Pot Elasticsearch host does not resolve.
	// Restarting the container has been the remedy since the first version.
	upstreamFailure = "UnknownHostException"
)

type backoff struct {
	hash     string
	failures int
	next     time.Time
}

// Reconciler is not safe for concurrent use; one goroutine owns it.
type Reconciler struct {
	rt    docker.Runtime
	cfg   config.Config
	dir   state.Dir
	log   *zap.Logger
	now   func() time.Time
	state map[string]*backoff
}

func New(rt docker.Runtime, cfg config.Config, log *zap.Logger) *Reconciler {
	return &Reconciler{rt: rt, cfg: cfg, dir: state.Dir(cfg.StateDir), log: log, now: time.Now, state: map[string]*backoff{}}
}

// Status is the outcome of one pass.
type Status struct {
	// Healthy is true when every container the settings ask for is running
	// and healthy. Only then is a heartbeat sent.
	Healthy  bool
	Problems []string
}

// Reconcile creates, recreates or removes containers so they match s.
func (r *Reconciler) Reconcile(ctx context.Context, s nfg.Settings) Status {
	var st Status
	problem := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		st.Problems = append(st.Problems, msg)
		r.log.Warn(msg)
	}

	running, err := r.rt.List(ctx)
	if err != nil {
		problem("cannot list containers: %v", err)
		return st
	}
	byName := map[string]docker.Container{}
	for _, c := range running {
		byName[c.Name] = c
	}

	units := desired(r.cfg, r.dir, s)
	want := map[string]bool{}
	for _, u := range units {
		want[u.spec.Name] = true
	}
	for name := range byName {
		if !want[name] {
			r.log.Info("removing container no longer wanted", zap.String("container", name))
			if err := r.rt.Remove(ctx, name); err != nil {
				problem("remove %s: %v", name, err)
			}
			delete(r.state, name)
		}
	}

	for _, u := range units {
		if msg := r.ensure(ctx, u, byName); msg != "" {
			problem("%s: %s", u.spec.Name, msg)
		}
	}
	st.Healthy = len(st.Problems) == 0
	return st
}

// ensure brings one unit to its desired state and returns why it is not
// healthy yet, or "".
func (r *Reconciler) ensure(ctx context.Context, u unit, byName map[string]docker.Container) string {
	c, exists := byName[u.spec.Name]
	if u.err != nil {
		if exists {
			if err := r.rt.Remove(ctx, u.spec.Name); err != nil {
				return fmt.Sprintf("%v; remove: %v", u.err, err)
			}
		}
		return u.err.Error()
	}
	hash := u.spec.Hash()
	b := r.state[u.spec.Name]
	if b == nil || b.hash != hash {
		// New or changed settings are acted on at once.
		b = &backoff{hash: hash}
		r.state[u.spec.Name] = b
	}

	reason := ""
	switch {
	case !exists:
		reason = "not created"
	case c.Hash != hash:
		reason = "settings changed"
	case !c.Running:
		reason = "not running"
	case c.Health == "unhealthy":
		reason = "docker health check failing"
	case u.checkLogs:
		logs, err := r.rt.Logs(ctx, u.spec.Name, logTail)
		if err != nil {
			return "cannot read logs: " + err.Error()
		}
		if strings.Contains(logs, upstreamFailure) {
			reason = "Elasticsearch host unreachable (" + upstreamFailure + ")"
		}
	}
	if reason == "" {
		b.failures, b.next = 0, time.Time{}
		return ""
	}

	if now := r.now(); now.Before(b.next) {
		return fmt.Sprintf("%s, next attempt in %s", reason, b.next.Sub(now).Round(time.Second))
	}
	if err := r.start(ctx, u); err != nil {
		r.fail(b)
		return fmt.Sprintf("%s, start failed: %v", reason, err)
	}
	// A container that has to be started again later is counted as a failure,
	// so a crash loop backs off.
	if exists && c.Hash == hash {
		r.fail(b)
	}
	r.log.Info("container started", zap.String("container", u.spec.Name), zap.String("reason", reason), zap.String("hash", hash))
	return reason + ", started"
}

func (r *Reconciler) fail(b *backoff) {
	b.failures++
	d := firstBackoff << (b.failures - 1)
	if d > maxBackoff || d <= 0 {
		d = maxBackoff
	}
	b.next = r.now().Add(d)
}

func (r *Reconciler) start(ctx context.Context, u unit) error {
	if u.spec.Network != "" {
		ok, err := r.rt.NetworkExists(ctx, u.spec.Network)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("docker network %s does not exist (is T-Pot running?)", u.spec.Network)
		}
	}
	for name, content := range u.files {
		if _, err := r.dir.WriteFile(name, content); err != nil {
			return err
		}
	}
	if err := r.rt.Remove(ctx, u.spec.Name); err != nil {
		return err
	}
	return r.rt.Run(ctx, u.spec)
}

// RemoveLegacy removes containers with our names that are not labelled as
// managed: the docker compose containers of versions before the reconciler.
func (r *Reconciler) RemoveLegacy(ctx context.Context) {
	cs, err := r.rt.List(ctx)
	if err != nil {
		return
	}
	managed := map[string]bool{}
	for _, c := range cs {
		managed[c.Name] = true
	}
	for _, name := range []string{SyslogName, LogstashName} {
		if !managed[name] {
			_ = r.rt.Remove(ctx, name)
		}
	}
}

// RemoveAll removes every managed container; used on shutdown.
func (r *Reconciler) RemoveAll(ctx context.Context) {
	cs, err := r.rt.List(ctx)
	if err != nil {
		r.log.Warn("cannot list containers to remove", zap.Error(err))
		cs = []docker.Container{{Name: SyslogName}, {Name: LogstashName}}
	}
	for _, c := range cs {
		if err := r.rt.Remove(ctx, c.Name); err != nil {
			r.log.Warn("remove container", zap.String("container", c.Name), zap.Error(err))
			continue
		}
		r.log.Info("container removed", zap.String("container", c.Name))
	}
}
