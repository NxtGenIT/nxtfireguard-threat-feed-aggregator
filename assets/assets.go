package assets

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/models"
	"go.uber.org/zap"
)

//go:embed logo.txt
var LogoContent string

//go:embed logstash.yml
var logstashYmlContent string

//go:embed docker-compose.yml
var dockerComposeContent []byte

var (
	tempDir string
	mu      sync.Mutex // Protect tempDir creation
)

type ConfigType string

const (
	SyslogConfig   ConfigType = "syslog"
	LogstashConfig ConfigType = "logstash"
)

type ComposeOptions struct {
	ConfigContent  string
	ConfigType     ConfigType
	SyslogServices *models.SyslogServices // nil if not applicable
}

func GetDockerComposeFile(opts ComposeOptions) (string, error) {
	mu.Lock()
	defer mu.Unlock()

	// Create temp directory if it doesn't exist
	if tempDir == "" {
		var err error
		tempDir, err = os.MkdirTemp("", "nfgtfa-*")
		if err != nil {
			return "", fmt.Errorf("failed to create temp directory: %w", err)
		}
		zap.L().Debug("Created temp directory", zap.String("tempDir", tempDir))
	}

	// Start with the original docker-compose content
	updatedCompose := string(dockerComposeContent)

	// Handle config based on type
	if opts.ConfigContent != "" {
		var configFileName string
		var originalPath string

		switch opts.ConfigType {
		case SyslogConfig:
			configFileName = "syslog-ng.conf"
			originalPath = "../syslog/syslog-ng.conf"
			zap.L().Debug("Preparing syslog config",
				zap.String("configFile", configFileName),
				zap.String("originalPath", originalPath))
			if opts.SyslogServices != nil {
				updatedCompose = strings.ReplaceAll(
					updatedCompose,
					`      - "{{SYSLOG_PORTS}}"`,
					buildSyslogPorts(*opts.SyslogServices),
				)
			}

		case LogstashConfig:
			configFileName = "logstash.conf"
			originalPath = "../logstash/logstash.conf"
			zap.L().Debug("Preparing logstash config",
				zap.String("configFile", configFileName),
				zap.String("originalPath", originalPath))

			// Write logstash.yml in addition to the config
			ymlFile := filepath.Join(tempDir, "logstash.yml")
			if err := os.WriteFile(ymlFile, []byte(logstashYmlContent), 0644); err != nil {
				return "", fmt.Errorf("failed to create logstash.yml: %w", err)
			}
			zap.L().Info("Wrote logstash.yml", zap.String("path", ymlFile))

			updatedCompose = strings.ReplaceAll(updatedCompose, "../logstash/logstash.yml", ymlFile)

		default:
			return "", fmt.Errorf("unsupported config type: %s", opts.ConfigType)
		}

		// Write config to temp file
		configFile := filepath.Join(tempDir, configFileName)
		err := os.WriteFile(configFile, []byte(opts.ConfigContent), 0644)
		if err != nil {
			return "", fmt.Errorf("failed to create %s config file: %w", opts.ConfigType, err)
		}
		zap.L().Debug("Wrote config file", zap.String("path", configFile))

		// Replace the relative path with absolute temp file path
		updatedCompose = strings.ReplaceAll(updatedCompose, originalPath, configFile)
	}

	// Write the updated docker-compose file
	dockerComposeFile := filepath.Join(tempDir, "docker-compose.yml")
	err := os.WriteFile(dockerComposeFile, []byte(updatedCompose), 0644)
	if err != nil {
		return "", fmt.Errorf("failed to create docker-compose file: %w", err)
	}
	zap.L().Info("Wrote docker-compose.yml", zap.String("path", dockerComposeFile))
	zap.L().Debug("docker-compose.yml content", zap.String("content", updatedCompose[:min(len(updatedCompose), 1500)]))

	return dockerComposeFile, nil
}

// Cleanup removes all temporary files
func Cleanup() {
	mu.Lock()
	defer mu.Unlock()

	if tempDir != "" {
		os.RemoveAll(tempDir)
		tempDir = ""
	}
}

func buildSyslogPorts(s models.SyslogServices) string {
	var ports []string
	if s.SyslogCiscoFtdEnabled {
		ports = append(ports, "      - \"514:514/udp\"")
	}
	if s.SyslogCiscoIseEnabled {
		ports = append(ports, "      - \"1025:1025/udp\"")
	}
	if s.SyslogOpnsenseEnabled {
		ports = append(ports, "      - \"1026:1026/udp\"")
	}
	if s.SyslogSuricataEnabled {
		ports = append(ports, "      - \"1027:1027/udp\"")
	}
	return strings.Join(ports, "\n")
}
