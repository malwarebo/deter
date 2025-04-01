package mitigation

import (
	"log"
	"strings"

	cfAPI "github.com/malwarebo/deter/internal/api" 
	"github.com/malwarebo/deter/internal/config"
)


func ActivateMitigation(cfg *config.Config, cfClient *cfAPI.CloudflareClient, zoneID, kvKey string) string {
	log.Printf("INFO: Activating mitigations for zone %s", zoneID)
	actionStatus := []string{}

	
	err := cfClient.WriteKvValue(cfg.KVNamespaceID, kvKey, "active")
	if err != nil {
		log.Printf("ERROR: Failed to signal worker via KV (active): %v", err)
		actionStatus = append(actionStatus, "KV Signal FAILED")
	} else {
		log.Printf("INFO: Successfully signaled Worker via KV: %s = active", kvKey)
		actionStatus = append(actionStatus, "KV Signaled")
	}

	
	err = cfClient.SetSecurityLevel(zoneID, "under_attack")
	if err != nil {
		log.Printf("ERROR: Failed to set security level to 'under_attack': %v", err)
		actionStatus = append(actionStatus, "Security Level FAILED")
	} else {
		log.Printf("INFO: Successfully set security level to 'under_attack' for zone %s", zoneID)
		actionStatus = append(actionStatus, "Security Level Set")
	}

	

	return "Activated Mitigation (" + strings.Join(actionStatus, ", ") + ")"
}


func DeactivateMitigation(cfg *config.Config, cfClient *cfAPI.CloudflareClient, zoneID, kvKey string) string {
	log.Printf("INFO: Deactivating mitigations for zone %s", zoneID)
	actionStatus := []string{}

	
	err := cfClient.WriteKvValue(cfg.KVNamespaceID, kvKey, "inactive")
	if err != nil {
		log.Printf("ERROR: Failed to signal worker via KV (inactive): %v", err)
		actionStatus = append(actionStatus, "KV Signal FAILED")
	} else {
		log.Printf("INFO: Successfully signaled Worker via KV: %s = inactive", kvKey)
		actionStatus = append(actionStatus, "KV Signaled")
	}

	
	err = cfClient.SetSecurityLevel(zoneID, cfg.DefaultSecLevel)
	if err != nil {
		log.Printf("ERROR: Failed to revert security level to '%s': %v", cfg.DefaultSecLevel, err)
		actionStatus = append(actionStatus, "Security Level FAILED")
	} else {
		log.Printf("INFO: Successfully reverted security level to '%s' for zone %s", cfg.DefaultSecLevel, zoneID)
		actionStatus = append(actionStatus, "Security Level Set")
	}

	

	return "Deactivated Mitigation (" + strings.Join(actionStatus, ", ") + ")"
}