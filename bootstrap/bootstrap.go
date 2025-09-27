package bootstrap

import (
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/config"
	"go.uber.org/zap"
)

func InitializeSystem(cfg *config.Config) error {
	// Sync config
	if err := config.Sync(cfg); err != nil {
		return err
	}

	zap.L().Info("Threat Feed Aggregator bootstrapped successfully.")
	return nil
}
