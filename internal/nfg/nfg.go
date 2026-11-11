// Package nfg talks to the NxtFireGuard backend: the tfa-controller (settings
// and the update stream) and the heartbeat endpoint.
package nfg

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/config"
	"github.com/NxtGenIT/nxtfireguard-threat-feed-aggregator/internal/services"
)

// Settings is what the dashboard decides for this aggregator.
type Settings struct {
	SyslogEnabled   bool             `json:"syslogEnabled"`
	SyslogServices  services.Toggles `json:"syslogServices"`
	LogstashEnabled bool             `json:"logstashEnabled"`
}

type Client struct {
	cfg  config.Config
	http *http.Client
	tls  *tls.Config
	// retryDelay is the first backoff step; tests shorten it.
	retryDelay time.Duration
}

func New(cfg config.Config) *Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	var tc *tls.Config
	if cfg.SkipVerifyTLS {
		tc = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in via SKIP_VERIFY_TLS
		t.TLSClientConfig = tc
	}
	return &Client{cfg: cfg, http: &http.Client{Transport: t, Timeout: 30 * time.Second}, tls: tc, retryDelay: time.Second}
}

func (c *Client) controllerHeaders() http.Header {
	h := http.Header{}
	h.Set("X_AUTH_KEY", c.cfg.Key.Reveal())
	h.Set("X_AGGREGATOR_NAME", c.cfg.Name)
	return h
}

// FetchSettings is GET /sync/config.
func (c *Client) FetchSettings(ctx context.Context) (Settings, error) {
	var body struct {
		Config Settings `json:"config"`
	}
	err := c.do(ctx, c.cfg.ControllerURL+"/sync/config", c.controllerHeaders(), func(r io.Reader) error {
		return json.NewDecoder(r).Decode(&body)
	})
	return body.Config, err
}

// Heartbeat pings the heartbeat monitor.
func (c *Client) Heartbeat(ctx context.Context) error {
	h := http.Header{}
	h.Set("apikey", c.cfg.Key.Reveal())
	return c.do(ctx, c.cfg.HeartbeatURL+"/ping/"+c.cfg.HeartbeatID, h, nil)
}

// StatusError is a non-2xx answer that retrying won't fix.
type StatusError struct {
	URL    string
	Status int
}

func (e *StatusError) Error() string { return fmt.Sprintf("GET %s: HTTP %d", e.URL, e.Status) }

// do GETs url, retrying network errors and 5xx three times with doubling delay.
func (c *Client) do(ctx context.Context, url string, h http.Header, decode func(io.Reader) error) error {
	delay := c.retryDelay
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
			delay *= 2
		}
		var retry bool
		retry, err = c.once(ctx, url, h, decode)
		if !retry {
			return err
		}
	}
	return err
}

func (c *Client) once(ctx context.Context, url string, h http.Header, decode func(io.Reader) error) (retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header = h
	resp, err := c.http.Do(req)
	if err != nil {
		return ctx.Err() == nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return resp.StatusCode >= 500, &StatusError{URL: url, Status: resp.StatusCode}
	}
	if decode == nil {
		return false, nil
	}
	if err := decode(resp.Body); err != nil {
		return false, fmt.Errorf("decode %s: %w", url, err)
	}
	return false, nil
}
