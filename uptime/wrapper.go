package uptime

import (
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/config"
	"go.uber.org/zap"
)

func Wrapper(cfg *config.Config) {
	syslogRunning, logstashRunning := MonitorServices(cfg.SyslogEnabled, cfg.LogstashEnabled)

	// Only consider the services that are enabled in the config
	allExpectedRunning := true
	if cfg.SyslogEnabled && !syslogRunning {
		allExpectedRunning = false
	}
	if cfg.LogstashEnabled && !logstashRunning {
		allExpectedRunning = false
	}

	if allExpectedRunning {
		// all services that should be running are indeed running
		SendHeartbeat(cfg.AggregatorName, cfg.AuthSecret, cfg.HeartbeatIdentifier, cfg.HeartbeatUrl)
	} else {
		// at least one expected service is down -> no heartbeat
		zap.L().Warn("Not all expected services are running, skipping heartbeat",
			zap.Bool("syslogExpected", cfg.SyslogEnabled),
			zap.Bool("syslogRunning", syslogRunning),
			zap.Bool("logstashExpected", cfg.LogstashEnabled),
			zap.Bool("logstashRunning", logstashRunning),
		)
	}
}
