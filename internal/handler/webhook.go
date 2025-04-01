package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io" // Updated from io/ioutil
	"log"
	"net/http"
	"time"

	cfAPI "github.com/malwarebo/deter/internal/api"
	"github.com/malwarebo/deter/internal/config"
	"github.com/malwarebo/deter/internal/mitigation"
)

type CloudflareDDoSWebhook struct {
	AlertID     string     `json:"alert_id"`
	AlertType   string     `json:"alert_type"`
	ZoneID      string     `json:"zone_id"`
	EndedAt     *time.Time `json:"ended_at"`
	SentAt      *time.Time `json:"sent_at"`
	StartedAt   *time.Time `json:"started_at"`
	Description string     `json:"description"`
	AttackID    string     `json:"attack_id"`
}

type WebhookHandler struct {
	cfg      *config.Config
	cfClient *cfAPI.CloudflareClient
}

func NewWebhookHandler(cfg *config.Config, cfClient *cfAPI.CloudflareClient) *WebhookHandler {
	return &WebhookHandler{
		cfg:      cfg,
		cfClient: cfClient,
	}
}

// ServeHTTP handles incoming webhook requests.
func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Create a context with timeout for processing the webhook
	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.WebhookTimeout)
	defer cancel()

	// Read body (it was already read by middleware, but we need it again)
	bodyBytes, err := io.ReadAll(r.Body) // Updated from ioutil.ReadAll
	if err != nil {
		log.Printf("ERROR: Webhook handler failed to re-read body: %v", err)
		http.Error(w, "Internal server error reading request", http.StatusInternalServerError)
		return
	}
	// Restore body just in case (though not strictly needed here anymore)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // Updated from ioutil.NopCloser
	defer r.Body.Close()

	// Parse payload
	// Try parsing as single object first
	var payload CloudflareDDoSWebhook
	err = json.Unmarshal(bodyBytes, &payload)
	if err != nil {
		// If single object fails, try parsing as an array (batch)
		var payloads []CloudflareDDoSWebhook
		errArray := json.Unmarshal(bodyBytes, &payloads)
		if errArray != nil || len(payloads) == 0 {
			log.Printf("ERROR: Failed to parse webhook JSON as object or array: %v / %v", err, errArray)
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}

		// Process all alerts in the batch instead of just the first one
		log.Printf("INFO: Processing %d alerts from batch.", len(payloads))

		// Process each alert sequentially
		for i, alertPayload := range payloads {
			log.Printf("INFO: Processing batch alert %d/%d: %s", i+1, len(payloads), alertPayload.AlertID)
			err = h.processAlert(ctx, w, alertPayload)
			if err != nil {
				// Log error but continue processing other alerts
				log.Printf("ERROR: Failed to process alert %s: %v", alertPayload.AlertID, err)
			}
		}

		// Return overall success response
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Processed %d webhook alerts", len(payloads))
		return
	}

	// Process single alert
	err = h.processAlert(ctx, w, payload)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error processing alert: %v", err), http.StatusInternalServerError)
		return
	}
}

// processAlert handles a single alert payload
func (h *WebhookHandler) processAlert(ctx context.Context, w http.ResponseWriter, payload CloudflareDDoSWebhook) error {
	log.Printf("INFO: Handling webhook for Alert Type: %s, Zone ID: %s, Attack ID: %s", payload.AlertType, payload.ZoneID, payload.AttackID)

	// Check if it's for the target zone
	if payload.ZoneID != h.cfg.TargetZoneID {
		log.Printf("INFO: Ignoring webhook for non-target zone %s", payload.ZoneID)
		return nil // Not an error, just skipping
	}

	// Determine Action (Attack Started vs Ended)
	// Use EndedAt field as primary indicator. Adjust if specific AlertTypes signal end.
	isAttackActive := payload.EndedAt == nil
	kvKey := h.cfg.KVKeyPrefix + payload.ZoneID
	var responseMsg string

	// --- Perform actions within the timeout context ---
	select {
	case <-ctx.Done():
		log.Printf("ERROR: Webhook processing timed out for Zone %s, Alert %s", payload.ZoneID, payload.AlertID)
		return fmt.Errorf("webhook processing timeout")
	default:
		// Proceed with mitigation logic
		if isAttackActive {
			responseMsg = mitigation.ActivateMitigation(h.cfg, h.cfClient, payload.ZoneID, kvKey)
		} else {
			responseMsg = mitigation.DeactivateMitigation(h.cfg, h.cfClient, payload.ZoneID, kvKey)
		}
	}

	// For single alerts, write response directly
	if w.Header().Get("Content-Type") == "" {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Webhook processed: %s", responseMsg)
	}

	return nil
}
