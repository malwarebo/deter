# Deter - Cloudflare DDoS Mitigation Automation

[![Go Build](https://github.com/malwarebo/deter/actions/workflows/go-build.yml/badge.svg)](https://github.com/malwarebo/deter/actions/workflows/go-build.yml)

Deter is a Go-based service that automatically responds to Cloudflare DDoS attack alerts by applying preconfigured mitigation strategies.

## Overview

Deter consists of two main components:

1. **Deter Server**: A Go application that receives Cloudflare webhook notifications about DDoS attacks and triggers appropriate security responses.
2. **Deter Worker**: A Cloudflare Worker that implements client-side challenges (e.g., proof-of-work) during active attacks.

Together, these components create a defense system that can:

- Automatically detect DDoS attacks via Cloudflare webhooks
- Apply appropriate security measures when attacks begin
- Scale back security measures when attacks end
- Apply client-side challenges to suspected malicious users

## Architecture

```
┌───────────────┐    Webhook    ┌─────────────────┐    API     ┌───────────────┐
│   Cloudflare  │ ────────────> │  Deter Server   │ ─────────> │   Cloudflare  │
│               │ <───────────  │                 │ <───────── │   API         │
└───────────────┘  HTTP 200 OK  └─────────────────┘            └───────────────┘
                                        │
                                        │ KV Write
                                        ▼
                                ┌─────────────────┐
                                │  KV Namespace   │
                                └─────────────────┘
                                        │
                                        │ KV Read
                                        ▼
┌───────────────┐     HTTP      ┌─────────────────┐
│    Browser    │ <────────────>│  Deter Worker   │
└───────────────┘                └─────────────────┘
```

## Features

- Webhook signature verification for security
- Automatic "Under Attack Mode" activation during attacks
- KV-based signaling between server and worker
- Configurable security levels and mitigations
- Client-side proof-of-work challenges via Workers
- Graceful shutdown for the server

## Setup and Configuration

### Server Requirements

- Go 1.18 or higher
- Cloudflare API Token with appropriate permissions
- Cloudflare Webhook endpoint configured

### Configuration (Environment Variables)

| Variable | Description | Required |
|----------|-------------|----------|
| `CF_WEBHOOK_SECRET` | Secret for verifying webhook signatures | Yes |
| `CF_API_TOKEN` | Cloudflare API token | Yes |
| `CF_ACCOUNT_ID` | Cloudflare account ID | Yes |
| `TARGET_ZONE_ID` | Zone ID to protect | Yes |
| `KV_NAMESPACE_ID` | KV namespace for state sharing | Yes |
| `LISTEN_ADDR` | Server listen address (default: `:8080`) | No |
| `DEFAULT_SEC_LEVEL` | Default security level (default: `medium`) | No |
| `KV_KEY_PREFIX` | Prefix for KV keys (default: `attack_status_zone_`) | No |
| `WEBHOOK_TIMEOUT_SECONDS` | Webhook processing timeout (default: `30`) | No |

### Worker Setup

1. Copy the worker code to your Cloudflare Worker
2. Configure `wrangler.toml` with your account/zone details
3. Create a KV namespace and update your worker configuration

## Running the Server

```bash
# Build the server
go build -o deter-server ./cmd/deter-server

# Run with environment variables set
export CF_WEBHOOK_SECRET="your-webhook-secret"
export CF_API_TOKEN="your-cf-api-token" 
export CF_ACCOUNT_ID="your-account-id"
export TARGET_ZONE_ID="your-zone-id"
export KV_NAMESPACE_ID="your-kv-namespace-id"
./deter-server
```

## API Reference

### Webhook Endpoint

**POST** `/cloudflare-webhook`

This endpoint receives DDoS event notifications from Cloudflare. Headers must include a valid `Cf-Webhook-Signature` for verification.

## Security Considerations

- Always use webhook signature verification in production
- Configure appropriate Cloudflare API token permissions
- Consider implementing timestamp validation to prevent replay attacks
