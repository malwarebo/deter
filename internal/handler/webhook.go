package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
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

func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.WebhookTimeout)
	defer cancel()

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("ERROR: Webhook handler failed to re-read body: %v", err)
		http.Error(w, "Internal server error reading request", http.StatusInternalServerError)
		return
	}

	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	defer r.Body.Close()

	var payload CloudflareDDoSWebhook
	err = json.Unmarshal(bodyBytes, &payload)
	if err != nil {

		var payloads []CloudflareDDoSWebhook
		errArray := json.Unmarshal(bodyBytes, &payloads)
		if errArray != nil || len(payloads) == 0 {
			log.Printf("ERROR: Failed to parse webhook JSON as object or array: %v / %v", err, errArray)
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}

		payload = payloads[0]
		log.Printf("INFO: Processing first alert from potential batch.")
	}

	log.Printf("INFO: Handling webhook for Alert Type: %s, Zone ID: %s, Attack ID: %s", payload.AlertType, payload.ZoneID, payload.AttackID)

	if payload.ZoneID != h.cfg.TargetZoneID {
		log.Printf("INFO: Ignoring webhook for non-target zone %s", payload.ZoneID)
		fmt.Fprintf(w, "Webhook ignored (non-target zone).")
		return
	}

	isAttackActive := payload.EndedAt == nil
	kvKey := h.cfg.KVKeyPrefix + payload.ZoneID
	var responseMsg string

	select {
	case <-ctx.Done():
		log.Printf("ERROR: Webhook processing timed out for Zone %s, Alert %s", payload.ZoneID, payload.AlertID)
		http.Error(w, "Webhook processing timeout", http.StatusGatewayTimeout)
		return
	default:

		if isAttackActive {
			responseMsg = mitigation.ActivateMitigation(h.cfg, h.cfClient, payload.ZoneID, kvKey)
		} else {
			responseMsg = mitigation.DeactivateMitigation(h.cfg, h.cfClient, payload.ZoneID, kvKey)
		}
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Webhook processed: %s", responseMsg)
}
