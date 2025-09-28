package uptime

import (
	"os/exec"
	"strings"

	"go.uber.org/zap"
)

func dockerPs(name string) string {
	out, _ := exec.Command("docker", "ps", "-f", "name="+name, "--format", "{{.Status}}").Output()
	return strings.TrimSpace(string(out))
}

func isLogstashContainerHealthy(name string) bool {
	out, err := exec.Command("docker", "logs", "--tail", "100", name).Output()
	if err != nil {
		zap.L().Error("Failed to get docker logs for health check", zap.String("container", name), zap.Error(err))
		return false
	}

	logs := string(out)
	zap.L().Debug("Recent container logs for health check",
		zap.String("container", name),
		zap.String("logs", logs),
	)

	// Check for Elasticsearch UnknownHostException in logs
	if strings.Contains(logs, "UnknownHostException") {
		zap.L().Warn("Detected Elasticsearch connectivity issues in container logs", zap.String("container", name))
		return false
	}

	return true
}

func isContainerRunning(name string) bool {
	status := dockerPs(name)
	return strings.HasPrefix(strings.ToLower(status), "up")
}

func MonitorServices(runSyslog bool, runLogstash bool) (bool, bool, bool) {
	var syslogRunning, logstashRunning, logstashHealthy bool

	if !runSyslog && !runLogstash {
		zap.L().Info("No services enabled to monitor.") // all good, nothing needs to run
		return true, true, true
	}

	if runSyslog {
		syslogRunning = isContainerRunning("nfg-syslog")
		if syslogRunning {
			zap.L().Info("Syslog container is running")
		} else {
			zap.L().Warn("Syslog container is not running")
		}
	}

	if runLogstash {
		logstashRunning = isContainerRunning("nfg-logstash")
		if logstashRunning {
			zap.L().Info("Logstash container is running")
		} else {
			zap.L().Warn("Logstash container is not running")
		}

		logstashHealthy = isLogstashContainerHealthy("nfg-logstash")
		if logstashHealthy {
			zap.L().Info("Logstash container is healthy")
		} else {
			zap.L().Warn("Logstash container is unhealthy")
		}
	}

	return syslogRunning, logstashRunning, logstashHealthy
}
