// Package network provides networking functionality for NDAgent.
package network

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/netdefense-io/ndagent/internal/config"
	"github.com/netdefense-io/ndagent/internal/logging"
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
	TokenUUID  string `json:"token_uuid"`
	DeviceUUID string `json:"device_uuid"`
	Name       string `json:"name"`
	Version    string `json:"version"`
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

	reqBody := StartRegistrationRequest{
		TokenUUID:  r.cfg.Token,
		DeviceUUID: r.cfg.DeviceUUID,
		Name:       hostname,
		Version:    version.Version,
	}

	log.Infow("Starting registration",
		"url", r.cfg.ServerURIStart,
		"device_uuid", r.cfg.DeviceUUID,
		"hostname", hostname,
		"version", version.Version,
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
		log.Errorw("Failed to start registration",
			"status_code", resp.StatusCode,
		)
		return fmt.Errorf("registration start failed with status: %d", resp.StatusCode)
	}

	log.Infow("Started registration process",
		"device_uuid", r.cfg.DeviceUUID,
	)

	return nil
}

// WaitForRegistration polls the server until the device is registered and enabled.
// Returns nil when device is enabled, or an error if device is disabled/deleted or context cancelled.
func (r *RegistrationClient) WaitForRegistration(ctx context.Context) error {
	log := logging.Named("registration")

	// Initialize delay tracking for exponential backoff
	var totalDelay float64
	const maxTotalDelay = 60.0 // Cap at around 1 minute
	const statusPollInterval = 10 * time.Second

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
			if err := r.StartRegistration(ctx); err != nil {
				log.Warnw("Failed to start registration",
					"error", err,
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
