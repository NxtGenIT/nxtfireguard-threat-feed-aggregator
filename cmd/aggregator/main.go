package main

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/assets"
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/bootstrap"
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/config"
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/uptime"
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/utils"
	"github.com/joho/godotenv"
	"go.uber.org/zap"
)

func main() {
	fmt.Print(assets.LogoContent)

	godotenv.Load()
	cfg := config.Load()

	log.Printf("Config loaded: %+v", cfg)

	utils.InitLogger(cfg)

	zap.L().Info("Threat Feed Aggregator starting up...")

	if err := bootstrap.InitializeSystem(cfg); err != nil {
		zap.L().Fatal("Startup failed", zap.Error(err))
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// WebSocket for receiving config updates
	configUpdater := config.NewWebsocketImpl()

	// Start Update WebSocket
	go func() {
		defer wg.Done()
		err := config.StartWebSocketClient(cfg, configUpdater)
		if err != nil {
			zap.L().Fatal("Config Updater WebSocket client failed to start", zap.Error((err)))
			os.Exit(1)
		}
	}()

	// Start sending heartbeats
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			uptime.Wrapper(cfg)
			<-ticker.C
		}
	}()

	wg.Wait()
}
