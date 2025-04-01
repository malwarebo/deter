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
		WebhookSecret:   getEnv("CF_WEBHOOK_SECRET", ""),
		CfAPIToken:      getEnv("CF_API_TOKEN", ""),
		CfAccountID:     getEnv("CF_ACCOUNT_ID", ""),
		TargetZoneID:    getEnv("TARGET_ZONE_ID", ""),
		KVNamespaceID:   getEnv("KV_NAMESPACE_ID", ""),
		ListenAddr:      getEnv("LISTEN_ADDR", ":8080"),
		DefaultSecLevel: getEnv("DEFAULT_SEC_LEVEL", "medium"),
		KVKeyPrefix:     getEnv("KV_KEY_PREFIX", "attack_status_zone_"),
		WebhookTimeout:  getEnvDuration("WEBHOOK_TIMEOUT_SECONDS", 30*time.Second),
	}

	if cfg.CfAPIToken == "" || cfg.CfAccountID == "" || cfg.TargetZoneID == "" || cfg.KVNamespaceID == "" {
		log.Fatal("FATAL: Missing required environment variables: CF_API_TOKEN, CF_ACCOUNT_ID, TARGET_ZONE_ID, KV_NAMESPACE_ID must be set.")
	}

	if cfg.WebhookSecret == "" {
		log.Println("WARN: CF_WEBHOOK_SECRET is not set. Webhook signature verification will be skipped (INSECURE!)")
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
