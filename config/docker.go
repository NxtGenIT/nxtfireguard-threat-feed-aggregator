package config

import (
	"fmt"
	"os/exec"

	"go.uber.org/zap"
)

func startContainer(name string) error {
	zap.L().Info("Starting container", zap.String("name", name))
	_, err := exec.Command("docker", "compose", "-f", "docker-compose.yml", "up", "-d", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start container %s: %w", name, err)
	}
	return nil
}

func stopContainer(name string) error {
	zap.L().Info("Stopping container", zap.String("name", name))
	_, err := exec.Command("docker", "compose", "-f", "docker-compose.yml", "down", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop container %s: %w", name, err)
	}
	return nil
}
