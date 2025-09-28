package uptime

import (
	"time"

	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/config"
	"go.uber.org/zap"
)

var (
	lastLogstashRestart time.Time
	logstashBackoff     = time.Second * 30
)

func Wrapper(cfg *config.Config) {
	syslogRunning, logstashRunning, logstashHealthy := MonitorServices(cfg.SyslogEnabled, cfg.LogstashEnabled)

	// Only consider the services that are enabled in the config
	allExpectedRunning := true

	// Attempt to start Syslog if enabled but not running
	if cfg.SyslogEnabled && !syslogRunning {
		zap.L().Warn("Syslog container not running, attempting to start...")
		config.RestartSyslog(cfg)
		allExpectedRunning = false // still consider it "not fully running" this tick
	}

	// Attempt to start Logstash if enabled but not running
	if cfg.LogstashEnabled && (!logstashRunning || !logstashHealthy) {
		if time.Since(lastLogstashRestart) >= logstashBackoff {
			zap.L().Warn("Logstash is down or unhealthy, restarting...",
				zap.Duration("backoff", logstashBackoff),
			)
			config.RestartLogstash(cfg)
			lastLogstashRestart = time.Now()

			// increase backoff up to max 10 minutes
			if logstashBackoff < 10*time.Minute {
				logstashBackoff *= 2
			}
		} else {
			zap.L().Warn("Logstash unhealthy, waiting before next restart",
				zap.Duration("remaining", logstashBackoff-time.Since(lastLogstashRestart)),
			)
		}
		allExpectedRunning = false // still consider it "not fully running" this tick

	} else if cfg.LogstashEnabled && logstashRunning && logstashHealthy {
		// reset backoff if it recovers
		if logstashBackoff != 30*time.Second {
			zap.L().Info("Logstash healthy again, resetting backoff")
			logstashBackoff = 30 * time.Second
		}
	}

	if allExpectedRunning {
		// all services that should be running are indeed running and healthy
		SendHeartbeat(cfg.AggregatorName, cfg.AuthSecret, cfg.HeartbeatIdentifier, cfg.HeartbeatUrl)
	} else {
		// at least one expected service is down -> no heartbeat
		zap.L().Warn("Not all expected services are running, skipping heartbeat",
			zap.Bool("syslogExpected", cfg.SyslogEnabled),
			zap.Bool("syslogRunning", syslogRunning),
			zap.Bool("logstashExpected", cfg.LogstashEnabled),
			zap.Bool("logstashRunning", logstashRunning),
			zap.Bool("logstashHealthy", logstashHealthy),
		)
	}
}
