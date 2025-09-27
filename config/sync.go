package config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
)

func Sync(cfg *Config) error {
	var resp *http.Response

	maxRetries := 3
	backoff := time.Second

	zap.L().Info("Starting config sync",
		zap.String("url", fmt.Sprintf("%s/sync/config", cfg.NfgTfaControllerUrl)),
	)

	for attempt := 0; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequest("GET", fmt.Sprintf("%s/sync/config", cfg.NfgTfaControllerUrl), nil)
		if err != nil {
			zap.L().Error("Failed to create config sync request",
				zap.String("url", cfg.NfgTfaControllerUrl),
				zap.Error(err),
			)
			return fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("X_AUTH_KEY", cfg.AuthSecret)
		req.Header.Set("X_AGGREGATOR_NAME", cfg.AggregatorName)

		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			zap.L().Warn("Failed to fetch aggregator data, retrying",
				zap.Int("attempt", attempt+1),
				zap.String("url", cfg.NfgTfaControllerUrl),
				zap.Error(err),
			)
			if attempt < maxRetries {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			zap.L().Error("Failed to fetch aggregator data after retries",
				zap.Int("maxRetries", maxRetries),
				zap.String("url", cfg.NfgTfaControllerUrl),
				zap.Error(err),
			)
			return fmt.Errorf("failed to fetch data after retries: %w", err)
		}

		if resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()

			var response ConfigResponse
			if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
				zap.L().Error("Failed to decode aggregator response",
					zap.String("url", cfg.NfgTfaControllerUrl),
					zap.Error(err),
				)
				return fmt.Errorf("failed to decode response: %w", err)
			}

			// update cfg with fetched values
			cfg.SetSyslogEnabled(response.Config.SyslogEnabled)
			cfg.SetLogstashEnabled(response.Config.LogstashEnabled)

			zap.L().Info("Stored config",
				zap.Bool("syslogEnabled", cfg.SyslogEnabled),
				zap.Bool("logstashEnabled", cfg.LogstashEnabled),
			)
			return nil
		}

		resp.Body.Close()

		// Retry on 5xx status codes
		if resp.StatusCode >= 500 && attempt < maxRetries {
			zap.L().Warn("Server error during config sync, retrying",
				zap.Int("attempt", attempt+1),
				zap.String("url", cfg.NfgTfaControllerUrl),
				zap.Int("status", resp.StatusCode),
			)
			time.Sleep(backoff)
			backoff *= 2
			continue
		}

		zap.L().Error("Config sync API returned non-retriable status",
			zap.String("url", cfg.NfgTfaControllerUrl),
			zap.Int("status", resp.StatusCode),
			zap.String("statusText", resp.Status),
		)
		return fmt.Errorf("config sync API returned status %s", resp.Status)
	}

	zap.L().Error("Config sync failed after all retries",
		zap.Int("maxRetries", maxRetries),
		zap.String("url", cfg.NfgTfaControllerUrl),
	)
	return fmt.Errorf("config sync failed after %d retries", maxRetries)

}
