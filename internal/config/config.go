package config

import (
	"log"
	"os"
	"strconv"
	"time"
)

type Config struct {
	WebhookSecret   string
	CfAPIToken      string
	CfAccountID     string
	TargetZoneID    string
	KVNamespaceID   string
	ListenAddr      string
	DefaultSecLevel string
	KVKeyPrefix     string
	WebhookTimeout  time.Duration
}

func LoadConfig() *Config {
	cfg := &Config{
		WebhookSecret:   getEnv("CF_WEBHOOK_SECRET", ""), // Required
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
	var missingVars []string

	if cfg.CfAPIToken == "" {
		missingVars = append(missingVars, "CF_API_TOKEN")
	}
	if cfg.CfAccountID == "" {
		missingVars = append(missingVars, "CF_ACCOUNT_ID")
	}
	if cfg.TargetZoneID == "" {
		missingVars = append(missingVars, "TARGET_ZONE_ID")
	}
	if cfg.KVNamespaceID == "" {
		missingVars = append(missingVars, "KV_NAMESPACE_ID")
	}
	if cfg.WebhookSecret == "" {
		missingVars = append(missingVars, "CF_WEBHOOK_SECRET")
	}

	if len(missingVars) > 0 {
		log.Fatalf("FATAL: Missing required environment variables: %v must be set.", missingVars)
	}

	log.Println("INFO: Configuration loaded successfully.")
	return cfg
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

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
