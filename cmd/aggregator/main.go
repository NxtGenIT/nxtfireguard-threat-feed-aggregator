package main

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
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

	if _, err := os.Stat(".env"); os.IsNotExist(err) {
		fmt.Println("ERROR: .env file not found in current directory")
		os.Exit(1)
	}

	// Setup shutdown hook
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)
	defer config.StopAllContainers() // fallback if main exits normally

	go func() {
		<-stopChan
		zap.L().Info("Received termination signal, stopping containers...")
		config.StopAllContainers()
		config.PruneNetworks()
		os.Exit(0)
	}()

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

	// Periodically sync config in case the WebSocket missed an update
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			config.Sync(cfg)
			<-ticker.C
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
