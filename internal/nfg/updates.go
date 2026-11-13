package nfg

import (
	"context"
	"encoding/json"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

const (
	pingEvery   = 30 * time.Second
	readTimeout = 60 * time.Second
	writeWait   = 10 * time.Second
	minBackoff  = time.Second
	maxBackoff  = 5 * time.Minute
)

// Watch keeps the update stream open until ctx ends. After every (re)connect
// it calls resync, because pushes sent while disconnected are lost. Config
// pushes go to apply; any other message type also triggers resync.
func (c *Client) Watch(ctx context.Context, log *zap.Logger, resync func(), apply func(Settings)) {
	backoff := minBackoff
	for ctx.Err() == nil {
		connected := time.Now()
		err := c.stream(ctx, resync, apply)
		if ctx.Err() != nil {
			return
		}
		// A connection that stayed up for a while was a healthy one; start over.
		if time.Since(connected) > maxBackoff {
			backoff = minBackoff
		}
		log.Warn("update stream down", zap.String("url", c.cfg.ControllerWSURL), zap.Error(err), zap.Duration("retryIn", backoff))
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

func (c *Client) stream(ctx context.Context, resync func(), apply func(Settings)) error {
	dialer := *websocket.DefaultDialer
	dialer.TLSClientConfig = c.tls
	conn, resp, err := dialer.DialContext(ctx, c.cfg.ControllerWSURL, c.controllerHeaders())
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return err
	}
	defer conn.Close()

	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		t := time.NewTicker(pingEvery)
		defer t.Stop()
		for {
			select {
			case <-connCtx.Done():
				// Unblocks ReadMessage on shutdown.
				_ = conn.Close()
				return
			case <-t.C:
				if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeWait)); err != nil {
					_ = conn.Close()
					return
				}
			}
		}
	}()

	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	conn.SetPongHandler(func(string) error { return conn.SetReadDeadline(time.Now().Add(readTimeout)) })
	// The controller pings too; answering resets our deadline as well.
	conn.SetPingHandler(func(data string) error {
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		return conn.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(writeWait))
	})

	resync()

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		var push struct {
			Type string `json:"type"`
			Settings
		}
		if err := json.Unmarshal(msg, &push); err != nil || push.Type != "config-update" {
			resync()
			continue
		}
		apply(push.Settings)
	}
}
