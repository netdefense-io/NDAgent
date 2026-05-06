// Package network provides networking functionality for NDAgent.
package network

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/logging"
	"github.com/netdefense-io/ndagent/internal/signing"
	"github.com/netdefense-io/ndagent/internal/util"
	"github.com/netdefense-io/ndagent/pkg/version"
)

// Registration status constants
const (
	StatusEnabled      = "ENABLED"
	StatusPending      = "PENDING"
	StatusUnregistered = "UNREGISTERED"
	StatusDisabled     = "DISABLED"
	StatusDeleted      = "DELETED"
)

// RegistrationStartError is returned by StartRegistration when the broker
// responds with a non-200 status. It carries the status code and a parsed
// Retry-After duration so the lifecycle's backoff can honor server hints
// (SlowAPI on the broker side sets Retry-After on its 429s).
type RegistrationStartError struct {
	StatusCode int
	RetryAfter time.Duration
}

func (e *RegistrationStartError) Error() string {
	return fmt.Sprintf("registration start failed with status: %d", e.StatusCode)
}

// IsTransient reports whether the error is worth retrying with backoff.
// 429 (rate-limited) and 5xx (server error / restart in progress) qualify.
// Other 4xx codes usually mean a config-time mistake the operator must
// fix; retrying the same request would just stay broken.
func (e *RegistrationStartError) IsTransient() bool {
	return e.StatusCode == http.StatusTooManyRequests ||
		e.StatusCode >= 500
}

// nextStartBackoff computes the next sleep duration for a transient
// StartRegistration failure (issue #18). Doubles the previous backoff with
// 0–5s of jitter, capped at max. If the server sent a Retry-After hint
// that's larger than the local computation, the hint wins — SlowAPI knows
// exactly when its sliding window will free up, so honoring it both
// reduces wasted retries AND avoids piling more requests onto a still-
// rate-limited window.
func nextStartBackoff(prev time.Duration, retryAfter, max time.Duration) time.Duration {
	const initial = 10 * time.Second
	jitter := time.Duration(rand.Int63n(int64(5 * time.Second)))
	var next time.Duration
	if prev <= 0 {
		next = initial + jitter
	} else {
		next = prev*2 + jitter
	}
	if next > max {
		next = max
	}
	if retryAfter > next {
		next = retryAfter
	}
	return next
}

// parseRetryAfter handles both forms of the Retry-After header:
// delta-seconds (RFC 9110 §10.2.3) and HTTP-date.
//
// Returns 0 on absence, malformed value, or a date already in the past —
// the caller treats 0 as "no server hint, fall back to local backoff".
func parseRetryAfter(header string) time.Duration {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(header); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if t, err := http.ParseTime(header); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// Registration errors
var (
	ErrDeviceDisabled = errors.New("device is disabled")
	ErrDeviceDeleted  = errors.New("device is deleted")
)

// RegistrationClient handles device registration with the server.
type RegistrationClient struct {
	cfg        *config.Config
	httpClient *http.Client
}

// CheckRegistrationRequest is the request body for registration check.
type CheckRegistrationRequest struct {
	TokenUUID  string `json:"token_uuid"`
	DeviceUUID string `json:"device_uuid"`
}

// CheckRegistrationResponse is the response from registration check.
type CheckRegistrationResponse struct {
	Status string `json:"status"`
}

// StartRegistrationRequest is the request body for starting registration.
type StartRegistrationRequest struct {
	TokenUUID    string `json:"token_uuid"`
	DeviceUUID   string `json:"device_uuid"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	DevicePubkey string `json:"device_pubkey,omitempty"` // base64 Ed25519 raw 32-byte pubkey (PAYLOAD-SIGNATURES-DESIGN.md §12.1)
	// BootstrapToken is sent only when the operator has issued a fresh
	// rebind token via the NDManager admin endpoint. See
	// PAYLOAD-SIGNATURES-FINDINGS-FIXES.md §3 Finding 2 / Layer 4.
	BootstrapToken string `json:"bootstrap_token,omitempty"`
}

// NewRegistrationClient creates a new registration client.
func NewRegistrationClient(cfg *config.Config) *RegistrationClient {
	return &RegistrationClient{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: cfg.GetTLSConfig(),
			},
		},
	}
}

// devicePubkeyBase64 derives the base64-encoded raw 32-byte Ed25519
// public key from the configured device_privkey seed. Returns an empty
// string + nil error if device_privkey is empty (shouldn't happen post-
// EnsureDevicePrivkey but kept defensive).
func (r *RegistrationClient) devicePubkeyBase64() (string, error) {
	if r.cfg.DevicePrivKey == "" {
		return "", nil
	}
	priv, err := signing.PrivateKeyFromBase64(r.cfg.DevicePrivKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signing.PublicKeyFromPrivate(priv)), nil
}

// CheckRegistration checks the device registration status with the server.
func (r *RegistrationClient) CheckRegistration(ctx context.Context) (string, error) {
	log := logging.Named("registration")

	reqBody := CheckRegistrationRequest{
		TokenUUID:  r.cfg.Token,
		DeviceUUID: r.cfg.DeviceUUID,
	}

	log.Infow("Requesting registration check",
		"url", r.cfg.ServerURICheck,
		"device_uuid", r.cfg.DeviceUUID,
	)

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", r.cfg.ServerURICheck, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("connection error during registration check: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Errorw("Failed to check registration",
			"status_code", resp.StatusCode,
		)
		return "", fmt.Errorf("registration check failed with status: %d", resp.StatusCode)
	}

	var respBody CheckRegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	log.Infow("Device registration status",
		"device_uuid", r.cfg.DeviceUUID,
		"status", respBody.Status,
	)

	return respBody.Status, nil
}

// StartRegistration initiates the registration process with the server.
func (r *RegistrationClient) StartRegistration(ctx context.Context) error {
	log := logging.Named("registration")

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	pubkeyB64, err := r.devicePubkeyBase64()
	if err != nil {
		return fmt.Errorf("derive device pubkey for registration: %w", err)
	}

	reqBody := StartRegistrationRequest{
		TokenUUID:      r.cfg.Token,
		DeviceUUID:     r.cfg.DeviceUUID,
		Name:           hostname,
		Version:        version.Version,
		DevicePubkey:   pubkeyB64,
		BootstrapToken: r.cfg.BootstrapToken,
	}

	log.Infow("Starting registration",
		"url", r.cfg.ServerURIStart,
		"device_uuid", r.cfg.DeviceUUID,
		"hostname", hostname,
		"version", version.Version,
		"device_pubkey_present", pubkeyB64 != "",
		"bootstrap_token_present", r.cfg.BootstrapToken != "",
	)

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", r.cfg.ServerURIStart, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("connection error during registration start: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
		log.Errorw("Failed to start registration",
			"status_code", resp.StatusCode,
			"retry_after", retryAfter,
		)
		return &RegistrationStartError{
			StatusCode: resp.StatusCode,
			RetryAfter: retryAfter,
		}
	}

	log.Infow("Started registration process",
		"device_uuid", r.cfg.DeviceUUID,
	)

	// Single-use semantics: zero the in-memory copy after a successful
	// StartRegistration. The OPNsense plugin's GUI field is the source of
	// truth — operators clear it manually after confirming the rebind on
	// the broker side. PAYLOAD-SIGNATURES-FINDINGS-FIXES.md §3 Finding 2 / Layer 4.
	if r.cfg.BootstrapToken != "" {
		r.cfg.BootstrapToken = ""
		log.Info("Bootstrap token cleared from in-memory config (single-use)")
	}

	return nil
}

// WaitForRegistration polls the server until the device is registered and enabled.
// Returns nil when device is enabled, or an error if device is disabled/deleted or context cancelled.
func (r *RegistrationClient) WaitForRegistration(ctx context.Context) error {
	log := logging.Named("registration")

	// Backoff state. Two independent trackers:
	//
	// `totalDelay` — accumulating delay used by the existing CheckRegistration
	// connection-error path. Pre-existing pattern; left intact.
	//
	// `startBackoff` — issue #18: separate tracker for transient
	// StartRegistration failures (429, 5xx). Without this, the agent would
	// retry Start every 10s and trap itself in the broker's 5/min rate
	// limiter forever. Resets to zero on a successful Start. Honors the
	// server's Retry-After header as a floor when present.
	var totalDelay float64
	var startBackoff time.Duration
	const maxTotalDelay = 60.0 // Cap at around 1 minute
	const statusPollInterval = 10 * time.Second
	const maxStartBackoff = 60 * time.Second

	for {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			log.Info("Registration wait cancelled")
			return ctx.Err()
		default:
		}

		status, err := r.CheckRegistration(ctx)
		if err != nil {
			// Handle connection errors with exponential backoff
			log.Errorw("Connection error during registration",
				"error", err,
			)

			// Calculate random delay for reconnection
			if totalDelay > maxTotalDelay {
				// If we're over the max, subtract a random amount
				subtractDelay := 5.0 + rand.Float64()*10.0 // 5-15 seconds
				totalDelay -= subtractDelay
			}

			// Add a new random delay
			newDelay := 10.0 + rand.Float64()*5.0 // 10-15 seconds
			totalDelay += newDelay

			actualDelay := time.Duration(totalDelay * float64(time.Second))
			log.Infow("Registration API connection failed, retrying",
				"delay_seconds", totalDelay,
			)

			if err := util.ShutdownAwareSleep(ctx, actualDelay); err != nil {
				log.Info("Registration retry cancelled during sleep")
				return err
			}
			continue
		}

		// Reset delay on successful connection
		totalDelay = 0

		switch status {
		case StatusEnabled:
			log.Infow("Device is registered and enabled",
				"device_uuid", r.cfg.DeviceUUID,
			)
			return nil

		case StatusPending:
			log.Infow("Device registration is pending, waiting for approval",
				"device_uuid", r.cfg.DeviceUUID,
			)
			if err := util.ShutdownAwareSleep(ctx, statusPollInterval); err != nil {
				return err
			}

		case StatusUnregistered:
			log.Infow("Device is not registered, starting registration",
				"device_uuid", r.cfg.DeviceUUID,
			)
			startErr := r.StartRegistration(ctx)
			if startErr == nil {
				// Success: reset Start backoff. Continue with the
				// normal poll cadence so the next Check sees the
				// updated server-side state.
				startBackoff = 0
			} else {
				var tErr *RegistrationStartError
				if errors.As(startErr, &tErr) && tErr.IsTransient() {
					startBackoff = nextStartBackoff(startBackoff, tErr.RetryAfter, maxStartBackoff)
					log.Warnw("Registration start transient failure, backing off",
						"status_code", tErr.StatusCode,
						"retry_after", tErr.RetryAfter,
						"next_attempt_in", startBackoff,
					)
					if err := util.ShutdownAwareSleep(ctx, startBackoff); err != nil {
						return err
					}
					continue
				}
				log.Warnw("Failed to start registration",
					"error", startErr,
				)
			}
			if err := util.ShutdownAwareSleep(ctx, statusPollInterval); err != nil {
				return err
			}

		case StatusDisabled:
			log.Warnw("Device is disabled",
				"device_uuid", r.cfg.DeviceUUID,
			)
			return ErrDeviceDisabled

		case StatusDeleted:
			log.Warnw("Device is deleted",
				"device_uuid", r.cfg.DeviceUUID,
			)
			return ErrDeviceDeleted

		default:
			log.Errorw("Unknown registration status",
				"status", status,
			)
			if err := util.ShutdownAwareSleep(ctx, statusPollInterval); err != nil {
				return err
			}
		}
	}
}
