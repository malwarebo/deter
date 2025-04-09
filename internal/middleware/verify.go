package middleware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"strings"
)

const cloudflareSignatureHeader = "Cf-Webhook-Signature"

func VerifyWebhookSignature(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			if secret == "" {
				log.Println("Skipping webhook signature verification: Secret not configured.")
				next.ServeHTTP(w, r)
				return
			}

			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				log.Printf("ERROR: Failed to read request body for signature verification: %v", err)
				http.Error(w, "Cannot read request body", http.StatusInternalServerError)
				return
			}

			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

			sigHeader := r.Header.Get(cloudflareSignatureHeader)
			if sigHeader == "" {
				log.Printf("WARN: Missing '%s' header", cloudflareSignatureHeader)
				http.Error(w, "Missing signature header", http.StatusUnauthorized)
				return
			}

			if !isValidSignature(sigHeader, bodyBytes, secret) {
				log.Printf("WARN: Invalid webhook signature received. Header: %s", sigHeader)
				http.Error(w, "Invalid signature", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func isValidSignature(signatureHeader string, body []byte, secret string) bool {

	parts := strings.Split(signatureHeader, ",")
	var sigTimestamp string
	var sigHex string

	for _, part := range parts {
		trimmedPart := strings.TrimSpace(part)
		if strings.HasPrefix(trimmedPart, "v1=") {
			sigHex = trimmedPart[3:]
		} else if strings.HasPrefix(trimmedPart, "t=") {
			sigTimestamp = trimmedPart[2:]
		}
	}

	if sigHex == "" || sigTimestamp == "" {
		log.Printf("WARN: Could not extract timestamp (t=) and signature (v1=) from header: %s", signatureHeader)
		return false
	}

	/*
		ts, err := strconv.ParseInt(sigTimestamp, 10, 64)
		if err != nil {
			log.Printf("WARN: Failed to parse timestamp '%s' from signature header: %v", sigTimestamp, err)
			return false
		}
		if time.Since(time.Unix(ts, 0)) > 5*time.Minute {
			log.Printf("WARN: Webhook timestamp %s is too old (outside tolerance window)", sigTimestamp)
			return false
		}
	*/

	receivedSig, err := hex.DecodeString(sigHex)
	if err != nil {
		log.Printf("WARN: Error decoding signature hex '%s': %v", sigHex, err)
		return false
	}

	signedPayload := []byte(sigTimestamp + ".")
	signedPayload = append(signedPayload, body...)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(signedPayload)
	expectedMAC := mac.Sum(nil)

	return hmac.Equal(receivedSig, expectedMAC)
}
