package main

import (
	"context" 
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

	
	cfg := config.LoadConfig()

	
	cfClient, err := cfAPI.NewCloudflareClient(cfg)
	if err != nil {
		log.Fatalf("FATAL: Failed to initialize Cloudflare client: %v", err)
	}
	log.Println("INFO: Cloudflare API client ready.")

	
	webhookHandler := handler.NewWebhookHandler(cfg, cfClient)

	
	mux := http.NewServeMux()
	
	verifiedWebhookHandler := middleware.VerifyWebhookSignature(cfg.WebhookSecret)(webhookHandler)
	mux.Handle("/cloudflare-webhook", verifiedWebhookHandler)

	
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})


	
	server := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: mux,
		
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	
	go func() {
		log.Printf("INFO: Listening on %s", cfg.ListenAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("FATAL: Could not listen on %s: %v\n", cfg.ListenAddr, err)
		}
	}()

	
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("INFO: Server is shutting down...")

	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) 
	defer cancel()

	
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("FATAL: Server forced to shutdown: %v", err)
	}

	log.Println("INFO: Server exited properly")
}