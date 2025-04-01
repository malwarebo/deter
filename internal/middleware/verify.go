package middleware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io" // Updated from io/ioutil
	"log"
	"net/http"
	"strconv" // Uncommented for timestamp validation
	"strings"
	"time" // Added for timestamp validation
)

const cloudflareSignatureHeader = "Cf-Webhook-Signature"

// VerifyWebhookSignature is middleware to verify Cloudflare webhook signatures.
func VerifyWebhookSignature(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If no secret is configured, reject the request (security improvement)
			if secret == "" {
				log.Println("ERROR: Cannot verify webhook signature: Secret not configured.")
				http.Error(w, "Webhook verification not configured", http.StatusInternalServerError)
				return
			}

			// Read body FIRST, because signature depends on it
			bodyBytes, err := io.ReadAll(r.Body) // Updated from ioutil.ReadAll
			if err != nil {
				log.Printf("ERROR: Failed to read request body for signature verification: %v", err)
				http.Error(w, "Cannot read request body", http.StatusInternalServerError)
				return
			}
			// Restore the body so the actual handler can read it
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // Updated from ioutil.NopCloser

			// Get signature header
			sigHeader := r.Header.Get(cloudflareSignatureHeader)
			if sigHeader == "" {
				log.Printf("WARN: Missing '%s' header", cloudflareSignatureHeader)
				http.Error(w, "Missing signature header", http.StatusUnauthorized)
				return
			}

			// Perform verification
			if !isValidSignature(sigHeader, bodyBytes, secret) {
				log.Printf("WARN: Invalid webhook signature received. Header: %s", sigHeader)
				http.Error(w, "Invalid signature", http.StatusUnauthorized)
				return
			}

			// Signature is valid, proceed to the actual handler
			next.ServeHTTP(w, r)
		})
	}
}

// isValidSignature performs the actual HMAC validation logic.
func isValidSignature(signatureHeader string, body []byte, secret string) bool {
	// Expected format: "v1=<timestamp>,v1=<signature>" or just "t=<ts>,v1=<sig>"
	// Let's parse flexibly
	parts := strings.Split(signatureHeader, ",")
	var sigTimestamp string
	var sigHex string

	for _, part := range parts {
		trimmedPart := strings.TrimSpace(part)
		if strings.HasPrefix(trimmedPart, "v1=") {
			sigHex = trimmedPart[3:] // Found the signature part
		} else if strings.HasPrefix(trimmedPart, "t=") {
			sigTimestamp = trimmedPart[2:] // Found the timestamp part
		}
	}

	if sigHex == "" || sigTimestamp == "" {
		log.Printf("WARN: Could not extract timestamp (t=) and signature (v1=) from header: %s", signatureHeader)
		return false
	}

	// Timestamp validation - Implement to prevent replay attacks
	ts, err := strconv.ParseInt(sigTimestamp, 10, 64)
	if err != nil {
		log.Printf("WARN: Failed to parse timestamp '%s' from signature header: %v", sigTimestamp, err)
		return false // Invalid timestamp format
	}

	// Reject if timestamp is too old (5 minute tolerance)
	if time.Since(time.Unix(ts, 0)) > 5*time.Minute {
		log.Printf("WARN: Webhook timestamp %s is too old (outside 5-minute tolerance window)", sigTimestamp)
		return false // Reject potentially replayed request
	}

	// Decode the hex signature from the header
	receivedSig, err := hex.DecodeString(sigHex)
	if err != nil {
		log.Printf("WARN: Error decoding signature hex '%s': %v", sigHex, err)
		return false
	}

	// Construct the signed payload: timestamp + "." + body
	signedPayload := []byte(sigTimestamp + ".")
	signedPayload = append(signedPayload, body...)

	// Calculate expected signature: HMAC-SHA256(secret, signed_payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(signedPayload)
	expectedMAC := mac.Sum(nil)

	// Compare using hmac.Equal (timing-safe)
	return hmac.Equal(receivedSig, expectedMAC)
}
