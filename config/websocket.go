package config

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

type ConfigUpdaterWsImpl struct {
	conn *websocket.Conn
	mu   sync.RWMutex
}

func NewWebsocketImpl() *ConfigUpdaterWsImpl {
	return &ConfigUpdaterWsImpl{}
}

func (u *ConfigUpdaterWsImpl) SetConn(c *websocket.Conn) {
	u.mu.Lock()
	u.conn = c
	u.mu.Unlock()
}

func (u *ConfigUpdaterWsImpl) GetConn() *websocket.Conn {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.conn
}

func (u *ConfigUpdaterWsImpl) StartListening(cfg *Config) {
	log.Print("started listening on websocket...")
	go func() {
		for {
			conn := u.GetConn()
			if conn == nil {
				time.Sleep(2 * time.Second)
				continue
			}

			conn.SetReadDeadline(time.Now().Add(60 * time.Second))
			conn.SetPongHandler(func(_ string) error {
				zap.L().Debug("[update] Received pong")
				conn.SetReadDeadline(time.Now().Add(60 * time.Second))
				return nil
			})

			for {
				_, msg, err := conn.ReadMessage()
				if err != nil {
					if wsCloseErr, ok := err.(*websocket.CloseError); ok {
						zap.L().Error("[update] Close error", zap.Int("code", wsCloseErr.Code), zap.String("text", wsCloseErr.Text))
					} else if errors.Is(err, io.EOF) {
						zap.L().Error("[update] EOF received")
					} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						zap.L().Error("[update] Read timeout", zap.Error(err))
					} else {
						zap.L().Error("[update] Read error", zap.Error(err))
					}
					u.SetConn(nil)
					break
				}

				var data UpdatedConfig
				if err := json.Unmarshal(msg, &data); err != nil {
					zap.L().Error("Failed to unmarshal update", zap.ByteString("payload", msg), zap.Error(err))
					continue
				}
				// update cfg with received values
				cfg.SetSyslogEnabled(data.SyslogEnabled)
				cfg.SetLogstashEnabled(data.LogstashEnabled)

				zap.L().Info("Stored config",
					zap.Bool("syslogEnabled", cfg.SyslogEnabled),
					zap.Bool("logstashEnabled", cfg.LogstashEnabled),
				)
			}
		}
	}()
}

func StartWebSocketClient(cfg *Config, configUpdater *ConfigUpdaterWsImpl) error {
	var scheme string
	if cfg.InsecureSkipVerifyTLS {
		scheme = "ws"
	} else {
		scheme = "wss"
	}

	u := url.URL{
		Scheme: scheme,
		Host:   cfg.NfgTfaControllerHost,
		Path:   "/sync/ws/updates",
	}
	headers := http.Header{}
	headers.Set("X_AUTH_KEY", cfg.AuthSecret)
	headers.Set("X_AGGREGATOR_NAME", cfg.AggregatorName)

	dialer := websocket.DefaultDialer
	if cfg.InsecureSkipVerifyTLS {
		dialer.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	for {
		zap.L().Info("[live] Connecting to config updater websocket", zap.String("url", u.String()))
		conn, _, err := dialer.Dial(u.String(), headers)
		if err != nil {
			zap.L().Error("[live] Failed to connect to config updater ws", zap.String("url", u.String()), zap.Error(err))
			time.Sleep(5 * time.Second)
			return err
		}

		zap.L().Info("[live] Connected to config updater ws")
		configUpdater.SetConn(conn)

		go PingKeepalive(configUpdater, cfg.WsKeepalivePeriod)
		configUpdater.StartListening(cfg)

		// Wait until disconnected
		for {
			time.Sleep(5 * time.Second)
			if configUpdater.GetConn() == nil {
				break
			}
		}

		zap.L().Warn("[update] WebSocket disconnected, retrying...")
	}
}

func PingKeepalive(configUpdater *ConfigUpdaterWsImpl, period time.Duration) {
	log.Printf("Starting config updater websocket keepalive pings every %s, ws client: %+v", period, configUpdater)
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		<-ticker.C
		configUpdater.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := configUpdater.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
			zap.L().Warn("[live] Failed to send client ping", zap.Error(err))
			configUpdater.conn.Close()
			break
		}
	}
}
