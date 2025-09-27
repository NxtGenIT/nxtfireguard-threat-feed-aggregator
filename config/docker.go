package config

import (
	"fmt"
	"os/exec"

	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/assets"
	"go.uber.org/zap"
)

func startContainer(name string) error {
	composeFile, err := assets.GetDockerComposeFile()
	if err != nil {
		return fmt.Errorf("failed to get docker-compose file: %w", err)
	}

	zap.L().Info("Starting container", zap.String("name", name))
	_, err = exec.Command("docker", "compose", "-f", composeFile, "up", "-d", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start container %s: %w", name, err)
	}
	return nil
}

func stopContainer(name string) error {
	composeFile, err := assets.GetDockerComposeFile()
	if err != nil {
		return fmt.Errorf("failed to get docker-compose file: %w", err)
	}

	zap.L().Info("Stopping container", zap.String("name", name))
	_, err = exec.Command("docker", "compose", "-f", composeFile, "down", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop container %s: %w", name, err)
	}
	return nil
}
