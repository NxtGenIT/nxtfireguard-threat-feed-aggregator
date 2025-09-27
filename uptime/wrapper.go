package uptime

import (
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/config"
	"go.uber.org/zap"
)

func Wrapper(cfg *config.Config) {
	syslogRunning, logstashRunning := MonitorServices(cfg.SyslogEnabled, cfg.LogstashEnabled)

	// Only consider the services that are enabled in the config
	allExpectedRunning := true

	// Attempt to start Syslog if enabled but not running
	if cfg.SyslogEnabled && !syslogRunning {
		zap.L().Warn("Syslog container not running, attempting to start...")
		config.HandleSyslogChange(cfg)
		allExpectedRunning = false // still consider it "not fully running" this tick
	}

	// Attempt to start Logstash if enabled but not running
	if cfg.LogstashEnabled && !logstashRunning {
		zap.L().Warn("Logstash container not running, attempting to start...")
		config.HandleLogstashChange(cfg)
		allExpectedRunning = false // still consider it "not fully running" this tick
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
