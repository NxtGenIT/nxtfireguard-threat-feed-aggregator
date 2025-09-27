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

func isContainerRunning(name string) bool {
	status := dockerPs(name)
	return strings.HasPrefix(strings.ToLower(status), "up")
}

func MonitorServices(runSyslog bool, runLogstash bool) (bool, bool) {
	var syslogRunning, logstashRunning bool

	if !runSyslog && !runLogstash {
		zap.L().Info("No services enabled to monitor.") // all good, nothing needs to run
		return true, true
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
	}

	return syslogRunning, logstashRunning
}
