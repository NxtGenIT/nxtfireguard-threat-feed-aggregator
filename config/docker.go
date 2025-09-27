package config

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/assets"
	"go.uber.org/zap"
)

func PruneNetworks() {
	output, err := exec.Command("docker", "network", "ls", "--format", "{{.Name}}").CombinedOutput()
	if err != nil {
		zap.L().Warn("Failed to list Docker networks", zap.Error(err), zap.String("output", string(output)))
	} else {
		networks := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, net := range networks {
			if strings.HasPrefix(net, "nfgtfa-") && strings.HasSuffix(net, "_default") {
				zap.L().Info("Removing temporary network", zap.String("network", net))
				out, err := exec.Command("docker", "network", "rm", net).CombinedOutput()
				if err != nil {
					zap.L().Warn("Failed to remove network", zap.String("network", net), zap.Error(err), zap.String("output", string(out)))
				} else {
					zap.L().Info("Removed network successfully", zap.String("network", net))
				}
			}
		}
	}
}

func StopAllContainers() {
	err := stopContainer("nfg-syslog")
	if err != nil {
		zap.L().Error("failed to stop container nfg-syslog:")
	}
	err = stopContainer("nfg-logstash")
	if err != nil {
		zap.L().Error("failed to stop container nfg-logstash:")
	}
}

func startContainer(name string, c *Config) error {
	var configContent string
	var configType assets.ConfigType

	// Get the appropriate config by container name
	switch name {
	case "nfg-syslog":
		configType = assets.SyslogConfig
		configContent = c.SyslogConfig
		if configContent == "" {
			return fmt.Errorf("syslog config is empty, cannot start container")
		}
	case "nfg-logstash":
		configType = assets.LogstashConfig
		configContent = c.LogstashConfig
		if configContent == "" {
			return fmt.Errorf("logstash config is empty, cannot start container")
		}
	default:
		configContent = ""
	}

	composeFile, err := assets.GetDockerComposeFile(configContent, configType)
	if err != nil {
		return fmt.Errorf("failed to get docker-compose file: %w", err)
	}

	zap.L().Info("Starting container", zap.String("name", name), zap.String("composeFile", composeFile))

	cmd := exec.Command("docker", "compose", "-f", composeFile, "up", "-d", name)
	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		zap.L().Info("docker compose output", zap.String("output", string(output)))
	}
	if err != nil {
		return fmt.Errorf("failed to start container %s: %w", name, err)
	}

	zap.L().Info("Container started successfully", zap.String("name", name))
	return nil
}

func stopContainer(name string) error {
	composeFile, err := assets.GetDockerComposeFile("", "")
	if err != nil {
		return fmt.Errorf("failed to get docker-compose file: %w", err)
	}

	zap.L().Info("Stopping container", zap.String("name", name))
	cmd := exec.Command("docker", "compose", "-f", composeFile, "down", name)
	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		zap.L().Info("docker compose output", zap.String("output", string(output)))
	}
	if err != nil {
		return fmt.Errorf("failed to stop container %s: %w", name, err)
	}

	zap.L().Info("Container stopped successfully", zap.String("name", name))
	return nil
}
