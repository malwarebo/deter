package mitigation

import (
	"log"
	"strings"

	cfAPI "github.com/malwarebo/deter/internal/api" // Use alias
	"github.com/malwarebo/deter/internal/config"
)

// ActivateMitigation performs actions to enable protection.
func ActivateMitigation(cfg *config.Config, cfClient *cfAPI.CloudflareClient, zoneID, kvKey string) string {
	log.Printf("INFO: Activating mitigations for zone %s", zoneID)
	actionStatus := []string{}

	// Action 1: Signal Worker via KV -> "active"
	err := cfClient.WriteKvValue(cfg.KVNamespaceID, kvKey, "active")
	if err != nil {
		log.Printf("ERROR: Failed to signal worker via KV (active): %v", err)
		actionStatus = append(actionStatus, "KV Signal FAILED")
	} else {
		log.Printf("INFO: Successfully signaled Worker via KV: %s = active", kvKey)
		actionStatus = append(actionStatus, "KV Signaled")
	}

	// Action 2: Set Security Level to "under_attack"
	err = cfClient.SetSecurityLevel(zoneID, "under_attack")
	if err != nil {
		log.Printf("ERROR: Failed to set security level to 'under_attack': %v", err)
		actionStatus = append(actionStatus, "Security Level FAILED")
	} else {
		log.Printf("INFO: Successfully set security level to 'under_attack' for zone %s", zoneID)
		actionStatus = append(actionStatus, "Security Level Set")
	}

	// Add calls to cfClient.CreateFirewallRule here if needed

	return "Activated Mitigation (" + strings.Join(actionStatus, ", ") + ")"
}

// DeactivateMitigation performs actions to disable protection.
func DeactivateMitigation(cfg *config.Config, cfClient *cfAPI.CloudflareClient, zoneID, kvKey string) string {
	log.Printf("INFO: Deactivating mitigations for zone %s", zoneID)
	actionStatus := []string{}

	// Action 1: Signal Worker via KV -> "inactive"
	err := cfClient.WriteKvValue(cfg.KVNamespaceID, kvKey, "inactive")
	if err != nil {
		log.Printf("ERROR: Failed to signal worker via KV (inactive): %v", err)
		actionStatus = append(actionStatus, "KV Signal FAILED")
	} else {
		log.Printf("INFO: Successfully signaled Worker via KV: %s = inactive", kvKey)
		actionStatus = append(actionStatus, "KV Signaled")
	}

	// Action 2: Set Security Level back to default
	err = cfClient.SetSecurityLevel(zoneID, cfg.DefaultSecLevel)
	if err != nil {
		log.Printf("ERROR: Failed to revert security level to '%s': %v", cfg.DefaultSecLevel, err)
		actionStatus = append(actionStatus, "Security Level FAILED")
	} else {
		log.Printf("INFO: Successfully reverted security level to '%s' for zone %s", cfg.DefaultSecLevel, zoneID)
		actionStatus = append(actionStatus, "Security Level Set")
	}

	// Add calls to cfClient.DeleteFirewallRule here if needed

	return "Deactivated Mitigation (" + strings.Join(actionStatus, ", ") + ")"
}