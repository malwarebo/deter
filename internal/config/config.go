package config

import (
	"log"
	"os"
	"strconv"
	"time"
)

// Config holds the application configuration.
type Config struct {
	WebhookSecret   string
	CfAPIToken      string
	CfAccountID     string
	TargetZoneID    string
	KVNamespaceID   string
	ListenAddr      string
	DefaultSecLevel string
	KVKeyPrefix     string
	WebhookTimeout  time.Duration // Optional: Timeout for webhook processing
}

// LoadConfig loads configuration from environment variables.
func LoadConfig() *Config {
	cfg := &Config{
		WebhookSecret:   getEnv("CF_WEBHOOK_SECRET", ""), // Required, but checked later
		CfAPIToken:      getEnv("CF_API_TOKEN", ""),      // Required
		CfAccountID:     getEnv("CF_ACCOUNT_ID", ""),     // Required
		TargetZoneID:    getEnv("TARGET_ZONE_ID", ""),    // Required
		KVNamespaceID:   getEnv("KV_NAMESPACE_ID", ""),   // Required
		ListenAddr:      getEnv("LISTEN_ADDR", ":8080"),
		DefaultSecLevel: getEnv("DEFAULT_SEC_LEVEL", "medium"),
		KVKeyPrefix:     getEnv("KV_KEY_PREFIX", "attack_status_zone_"),
		WebhookTimeout:  getEnvDuration("WEBHOOK_TIMEOUT_SECONDS", 30*time.Second),
	}

	// Validate required fields
	if cfg.CfAPIToken == "" || cfg.CfAccountID == "" || cfg.TargetZoneID == "" || cfg.KVNamespaceID == "" {
		log.Fatal("FATAL: Missing required environment variables: CF_API_TOKEN, CF_ACCOUNT_ID, TARGET_ZONE_ID, KV_NAMESPACE_ID must be set.")
	}
	// Warn if secret is missing, but allow for testing (middleware should handle enforcement)
	if cfg.WebhookSecret == "" {
		log.Println("WARN: CF_WEBHOOK_SECRET is not set. Webhook signature verification will be skipped (INSECURE!)")
	}

	log.Println("INFO: Configuration loaded successfully.")
	return cfg
}

// Helper function to get environment variables with a default value.
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

// Helper function to get environment variable as time.Duration.
func getEnvDuration(key string, fallback time.Duration) time.Duration {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return fallback
	}
	if seconds, err := strconv.Atoi(valueStr); err == nil {
		return time.Duration(seconds) * time.Second
	}
	log.Printf("WARN: Invalid duration format for %s: '%s'. Using default: %v", key, valueStr, fallback)
	return fallback
}