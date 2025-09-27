package config

import (
	"fmt"
	"os/exec"

	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/assets"
	"go.uber.org/zap"
)

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
