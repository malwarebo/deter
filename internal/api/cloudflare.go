package api

import (
	"context"
	"fmt"
	"log"

	"github.com/cloudflare/cloudflare-go"
	deterConfig "github.com/malwarebo/deter/internal/config" // Use alias
)

// CloudflareClient wraps the official Cloudflare Go SDK.
type CloudflareClient struct {
	api       *cloudflare.API
	accountID string
	ctx       context.Context
}

// NewCloudflareClient creates a new Cloudflare API client instance.
func NewCloudflareClient(cfg *deterConfig.Config) (*CloudflareClient, error) {
	api, err := cloudflare.NewWithAPIToken(cfg.CfAPIToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create cloudflare client: %w", err)
	}

	return &CloudflareClient{
		api:       api,
		accountID: cfg.CfAccountID,
		ctx:       context.Background(), // Use a background context for now
	}, nil
}

// SetSecurityLevel updates the security level for a given zone using UpdateZoneSetting
// with the correct UpdateZoneSettingParams struct and handling two return values.
func (c *CloudflareClient) SetSecurityLevel(zoneID, level string) error {
	log.Printf("API CALL: Setting security level for zone %s to %s", zoneID, level)
	rc := cloudflare.ZoneIdentifier(zoneID)
	settingID := "security_level" // The specific ID for this setting

	// Create the params struct as required by the SDK function
	params := cloudflare.UpdateZoneSettingParams{
		Name:  settingID,
		Value: level, // Value is likely an interface{} or specific type, string should work
	}

	// Call the API with the context, resource container, and params struct
	// Correctly handle the two return values (response, error), ignoring the response (_)
	_, err := c.api.UpdateZoneSetting(c.ctx, rc, params)
	if err != nil {
		return fmt.Errorf("failed to update zone setting '%s' to '%s' for zone %s: %w", settingID, level, zoneID, err)
	}
	return nil
}

// WriteKvValue writes a key-value pair to the configured Workers KV namespace.
// Corrected assignment to handle two return values from WriteWorkersKVEntry.
func (c *CloudflareClient) WriteKvValue(namespaceID, key, value string) error {
	log.Printf("API CALL: Writing to KV Namespace %s: Key=%s, Value=%s", namespaceID, key, value)
	rc := cloudflare.AccountIdentifier(c.accountID) // KV operates at account level

	// Create the params struct as required by the SDK function
	params := cloudflare.WriteWorkersKVEntryParams{
		NamespaceID: namespaceID,
		Key:         key,
		Value:       []byte(value), // Value needs to be a byte slice
	}

	// Correctly handle the two return values (response, error)
	// We ignore the response (_) if we only need to check the error.
	_, err := c.api.WriteWorkersKVEntry(c.ctx, rc, params)
	if err != nil {
		return fmt.Errorf("failed to write KV entry (Namespace: %s, Key: %s): %w", namespaceID, key, err)
	}
	return nil
}

/*
// --- Placeholder for Firewall Rule Helpers (Check SDK for updates here too if needed) ---
// These might need similar adjustments based on exact SDK function signatures & return values

// CreateFirewallRule adds a new firewall rule. Returns the rule ID or error.
func (c *CloudflareClient) CreateFirewallRule(zoneID, ruleName, filterExpression, action string) (string, error) {
	log.Printf("API CALL: Creating firewall rule '%s' for zone %s", ruleName, zoneID)
	rc := cloudflare.ZoneIdentifier(zoneID)

	filterID, err := c.findOrCreateFilter(zoneID, filterExpression)
	if err != nil {
		return "", err
	}

	rule := cloudflare.FirewallRule{
		Action:      action,
		Description: ruleName,
		Filter:      &cloudflare.FilterRule{ID: filterID},
		Priority:    cloudflare.IntPtr(1),
	}

	// Assuming CreateFirewallRules returns ([]FirewallRule, error)
	rulesResp, err := c.api.CreateFirewallRules(c.ctx, rc, []cloudflare.FirewallRule{rule})
	if err != nil {
		return "", fmt.Errorf("failed to create firewall rule '%s': %w", ruleName, err)
	}
	if len(rulesResp) == 0 {
		return "", fmt.Errorf("firewall rule creation for '%s' returned no results", ruleName)
	}

	log.Printf("INFO: Created Firewall Rule ID: %s", rulesResp[0].ID)
	return rulesResp[0].ID, nil
}

// DeleteFirewallRule removes a firewall rule by its ID.
func (c *CloudflareClient) DeleteFirewallRule(zoneID, ruleID string) error {
	log.Printf("API CALL: Deleting firewall rule ID '%s' for zone %s", ruleID, zoneID)
	rc := cloudflare.ZoneIdentifier(zoneID)
	// Assuming DeleteFirewallRule returns (FirewallRule, error) or just (error)
	// If it returns (FirewallRule, error), use: _, err := ...
	err := c.api.DeleteFirewallRule(c.ctx, rc, ruleID)
	if err != nil {
		return fmt.Errorf("failed to delete firewall rule ID '%s': %w", ruleID, err)
	}
	return nil
}

// findOrCreateFilter checks for an existing filter or creates a new one. Returns Filter ID.
func (c *CloudflareClient) findOrCreateFilter(zoneID, filterExpression string) (string, error) {
	rc := cloudflare.ZoneIdentifier(zoneID)
	// Assuming ListFilters returns (ListFiltersResponse, ResultInfo, error)
	filtersResp, _, err := c.api.ListFilters(c.ctx, rc, cloudflare.ListFiltersParams{Expression: filterExpression})
	if err != nil {
		return "", fmt.Errorf("failed to list filters for zone %s: %w", zoneID, err)
	}
	if len(filtersResp) > 0 {
		log.Printf("INFO: Found existing filter ID %s for expression '%s'", filtersResp[0].ID, filterExpression)
		return filtersResp[0].ID, nil
	}

	log.Printf("INFO: Creating new filter for expression in zone %s: %s", zoneID, filterExpression)
	// Assuming CreateFilter returns (Filter, error)
	filterResp, err := c.api.CreateFilter(c.ctx, rc, cloudflare.CreateFilterParams{Expression: filterExpression})
	if err != nil {
		return "", fmt.Errorf("failed to create filter for zone %s: %w", zoneID, err)
	}
	log.Printf("INFO: Created filter ID: %s", filterResp.ID)
	return filterResp.ID, nil
}
*/
