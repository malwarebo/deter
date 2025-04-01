package main

import (
	"context" // Required for graceful shutdown
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	cfAPI "github.com/malwarebo/deter/internal/api"
	"github.com/malwarebo/deter/internal/config"
	"github.com/malwarebo/deter/internal/handler"
	"github.com/malwarebo/deter/internal/middleware"
)

func main() {
	log.Println("INFO: Starting deter webhook server...")

	// Load Configuration
	cfg := config.LoadConfig()

	// Initialize Cloudflare Client
	cfClient, err := cfAPI.NewCloudflareClient(cfg)
	if err != nil {
		log.Fatalf("FATAL: Failed to initialize Cloudflare client: %v", err)
	}
	log.Println("INFO: Cloudflare API client ready.")

	// Create Handlers
	webhookHandler := handler.NewWebhookHandler(cfg, cfClient)

	// Setup Routing and Middleware
	mux := http.NewServeMux()
	// Apply signature verification middleware ONLY to the webhook endpoint
	verifiedWebhookHandler := middleware.VerifyWebhookSignature(cfg.WebhookSecret)(webhookHandler)
	mux.Handle("/cloudflare-webhook", verifiedWebhookHandler)

	// Basic health check endpoint (optional)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})


	// Configure HTTP Server with Graceful Shutdown
	server := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: mux,
		// Add timeouts for production readiness
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("INFO: Listening on %s", cfg.ListenAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("FATAL: Could not listen on %s: %v\n", cfg.ListenAddr, err)
		}
	}()

	// Wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("INFO: Server is shutting down...")

	// Create context with timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // 30 seconds to shutdown gracefully
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("FATAL: Server forced to shutdown: %v", err)
	}

	log.Println("INFO: Server exited properly")
}