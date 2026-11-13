// Command aggregator relays firewall syslog and T-Pot events to the
// NxtFireGuard threat collector, running syslog-ng and Logstash in docker as
// the dashboard settings ask for.
package main

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/config"
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/docker"
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/nfg"
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/reconcile"
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/state"
	"github.com/joho/godotenv"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// version is set at release time with -ldflags "-X main.version=...".
var version = "dev"

//go:embed logo.txt
var logo string

// Variables so the tests can run the loop faster.
var (
	checkEvery     = time.Minute
	resyncEvery    = time.Hour
	retrySyncAfter = time.Minute
)

// checkEveryOverride lets the end-to-end tests (e2e/) build a binary with a
// faster loop: go build -ldflags "-X main.checkEveryOverride=2s". Release
// builds leave it empty.
var checkEveryOverride string

const shutdownGrace = 30 * time.Second

func main() {
	fmt.Fprint(os.Stderr, logo)
	if checkEveryOverride != "" {
		d, err := time.ParseDuration(checkEveryOverride)
		if err != nil || d <= 0 {
			fmt.Fprintln(os.Stderr, "invalid checkEveryOverride:", checkEveryOverride)
			os.Exit(1)
		}
		checkEvery = d
	}
	// A .env next to the binary is the documented setup; real environment
	// variables win over it.
	if err := godotenv.Load(); err != nil && !os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "reading .env:", err)
		os.Exit(1)
	}
	cfg, warnings, err := config.Load(os.LookupEnv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration error:", err)
		os.Exit(1)
	}
	log := newLogger(cfg)
	defer func() { _ = log.Sync() }()
	for _, w := range warnings {
		log.Warn(w)
	}
	log.Info("starting", zap.String("version", version), zap.Any("config", cfg))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	run(ctx, cfg, log, docker.CLI{})
}

func newLogger(cfg config.Config) *zap.Logger {
	zc := zap.NewProductionConfig()
	zc.EncoderConfig.TimeKey = "timestamp"
	zc.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	zc.OutputPaths = []string{"stdout"}
	if cfg.Debug {
		zc.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}
	log, err := zc.Build()
	if err != nil {
		panic(err)
	}
	return log.With(zap.String("service", "nfg-threat-feed-aggregator"), zap.String("aggregator", cfg.Name))
}

func run(ctx context.Context, cfg config.Config, log *zap.Logger, rt docker.Runtime) {
	dir := state.Dir(cfg.StateDir)
	client := nfg.New(cfg)
	// The first Reconcile also removes what compose-based versions left.
	rec := reconcile.New(rt, cfg, log)

	var settings nfg.Settings
	known, err := dir.LoadJSON(state.SettingsFile, &settings)
	if err != nil {
		log.Warn("ignoring unreadable saved settings", zap.Error(err))
		known = false
	}
	if known {
		log.Info("starting from saved settings until the controller answers", zap.Any("settings", settings))
	}

	updates := make(chan nfg.Settings, 1)
	resync := make(chan struct{}, 1)
	heartbeat := make(chan struct{}, 1)
	trigger := func(ch chan struct{}) {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	// publish keeps only the newest settings for the main loop; the lock makes
	// drain-and-send atomic between the sync loop and the update stream.
	var publishMu sync.Mutex
	publish := func(s nfg.Settings) {
		publishMu.Lock()
		defer publishMu.Unlock()
		select {
		case <-updates:
		default:
		}
		updates <- s
	}

	go syncLoop(ctx, client, log, resync, publish)
	go client.Watch(ctx, log, func() { trigger(resync) }, func(s nfg.Settings) {
		log.Info("settings pushed", zap.Any("settings", s))
		publish(s)
	})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-heartbeat:
				if err := client.Heartbeat(ctx); err != nil && ctx.Err() == nil {
					log.Warn("heartbeat failed", zap.Error(err))
				}
			}
		}
	}()

	apply := func() {
		st := rec.Reconcile(ctx, settings)
		log.Debug("reconciled", zap.Bool("healthy", st.Healthy), zap.Strings("problems", st.Problems))
	}
	if known {
		apply()
	}

	tick := time.NewTicker(checkEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info("shutting down, removing containers")
			sctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
			rec.RemoveAll(sctx)
			cancel()
			return
		case s := <-updates:
			if known && s == settings {
				continue
			}
			settings, known = s, true
			if err := dir.SaveJSON(state.SettingsFile, settings); err != nil {
				log.Warn("cannot save settings", zap.Error(err))
			}
			log.Info("applying settings", zap.Any("settings", settings))
			apply()
		case <-tick.C:
			if !known {
				log.Warn("no settings from the controller yet, not sending heartbeat")
				continue
			}
			st := rec.Reconcile(ctx, settings)
			switch {
			case !st.Healthy:
				log.Warn("not all wanted containers are healthy, skipping heartbeat", zap.Strings("problems", st.Problems))
			case cfg.HeartbeatID != "":
				trigger(heartbeat)
			}
		}
	}
}

// syncLoop fetches the settings at start, when asked, and hourly, so pushes
// missed by the update stream are picked up. Failures are retried sooner.
func syncLoop(ctx context.Context, c *nfg.Client, log *zap.Logger, resync <-chan struct{}, publish func(nfg.Settings)) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-resync:
		case <-timer.C:
		}
		next := resyncEvery
		s, err := c.FetchSettings(ctx)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			log.Error("settings sync failed", zap.Error(err), zap.Duration("retryIn", retrySyncAfter))
			next = retrySyncAfter
		default:
			publish(s)
		}
		timer.Reset(next)
	}
}
