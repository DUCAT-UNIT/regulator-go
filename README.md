# DUCAT Oracle Gateway Server (Go)

A high-performance gateway server that bridges clients with the Chainlink CRE (Compute Runtime Environment) for privacy-preserving threshold price commitments.

## Overview

The gateway server handles:
- **Price Quote Creation**: Clients request threshold price commitments
- **Webhook Processing**: Receives signed responses from CRE
- **Liquidation Monitoring**: Polls at-risk vaults and triggers breach checks

## System Integration

The Regulator is the **orchestrator** - it runs the cron jobs that drive the liquidation system.

### Role in System

```
┌─────────────┐                      ┌─────────────┐
│   Client    │ ◄──────────────────► │  Regulator  │
│   (SDK)     │    REST API          │  (Gateway)  │
└─────────────┘                      └──────┬──────┘
                                            │
                    ┌───────────────────────┼───────────────────────┐
                    │                       │                       │
                    ▼                       ▼                       ▼
            ┌─────────────┐         ┌─────────────┐         ┌─────────────┐
            │     CRE     │         │ Nostr Relay │         │   Indexer   │
            │   (WASM)    │         │             │         │ (at-risk)   │
            └─────────────┘         └─────────────┘         └─────────────┘
```

### Background Jobs

| Job | Frequency | Action |
|-----|-----------|--------|
| **Liquidation Poller** | Every 90s | Poll indexer `/at-risk`, trigger CRE CHECK for each |
| **Cleanup Job** | Every 2min | Remove stale pending requests |

### Endpoints

| Endpoint | Method | Purpose | Called By |
|----------|--------|---------|-----------|
| `GET /api/quote?th=PRICE` | GET | Create threshold commitment | Client SDK |
| `GET /api/price` | GET | Get latest cached price | Client SDK |
| `POST /webhook/ducat` | POST | Receive CRE callback | CRE |
| `POST /check` | POST | Check if threshold breached | Internal (liquidation) |
| `GET /status/:id` | GET | Poll async request status | Client SDK |
| `GET /health` | GET | Liveness probe | Kubernetes |
| `GET /readiness` | GET | Readiness probe | Kubernetes |
| `GET /metrics` | GET | Prometheus metrics | Prometheus |

### Type Schema (v2.5 PriceQuote)

```go
type PriceQuote struct {
    // Server identity
    SrvNetwork   string   `json:"srv_network"`   // "main" | "test"
    SrvPubkey    string   `json:"srv_pubkey"`    // Oracle public key (hex)

    // Quote price (at commitment creation)
    QuoteOrigin  string   `json:"quote_origin"`  // "link" | "nostr" | "cre"
    QuotePrice   float64  `json:"quote_price"`   // BTC/USD price
    QuoteStamp   int64    `json:"quote_stamp"`   // Unix timestamp

    // Latest price (most recent observation)
    LatestOrigin string   `json:"latest_origin"`
    LatestPrice  float64  `json:"latest_price"`
    LatestStamp  int64    `json:"latest_stamp"`

    // Event price (at breach, if any)
    EventOrigin  *string  `json:"event_origin"`
    EventPrice   *float64 `json:"event_price"`
    EventStamp   *int64   `json:"event_stamp"`
    EventType    string   `json:"event_type"`    // "active" | "breach"

    // Threshold commitment
    TholdHash    string   `json:"thold_hash"`    // Hash160 (20 bytes hex)
    TholdKey     *string  `json:"thold_key"`     // Revealed on breach
    TholdPrice   float64  `json:"thold_price"`

    // State & signatures
    IsExpired    bool     `json:"is_expired"`
    ReqID        string   `json:"req_id"`        // Request ID hash
    ReqSig       string   `json:"req_sig"`       // Schnorr signature
}
```

**Note**: All prices are `float64` to match cre-hmac HMAC computation.

## Security Features

- **BIP-340 Schnorr Signature Verification**: All webhooks verified against expected CRE public key
- **Constant-Time Comparisons**: Prevents timing attacks on sensitive comparisons
- **Replay Attack Prevention**: Event ID caching with automatic cleanup
- **Timestamp Validation**: Rejects stale/future webhooks (5-minute window, 5-second clock skew)
- **Rate Limiting**: Per-IP token bucket rate limiting
- **Circuit Breaker**: Prevents cascading failures to CRE gateway
- **Request Body Limits**: Prevents memory exhaustion attacks

## CRE Integration

### Request Size Limits

CRE has a **30KB maximum request size** (including headers and body). The gateway automatically batches large liquidation requests:

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Batch Size | 500 vaults | ~22KB per batch (safely under 30KB) |
| Batch Delay | 10 seconds | Avoid CRE rate limits (429 errors) |

### Batch Processing

When the liquidation poller detects at-risk vaults:

1. Vaults are split into batches of 500
2. Each batch triggers a separate CRE `evaluate` workflow
3. 10-second delay between batches prevents rate limiting
4. Success/failure logged per batch with running totals

## Environment Variables

### Required
| Variable | Description |
|----------|-------------|
| `CRE_WORKFLOW_ID` | CRE workflow identifier |
| `DUCAT_AUTHORIZED_KEY` | Ethereum address authorized for CRE |
| `GATEWAY_CALLBACK_URL` | URL where CRE sends webhook responses |
| `DUCAT_PRIVATE_KEY` | 64-char hex private key for signing CRE requests |
| `CRE_WEBHOOK_PUBKEY` | Expected CRE public key (64-char hex) for webhook verification |

### Optional
| Variable | Default | Description |
|----------|---------|-------------|
| `CRE_GATEWAY_URL` | `https://01.gateway.zone-a.cre.chain.link` | CRE gateway endpoint |
| `PORT` | `8080` | Server port |
| `BLOCK_TIMEOUT_SECONDS` | `60` | Request timeout |
| `CLEANUP_INTERVAL_SECONDS` | `120` | Stale request cleanup interval |
| `MAX_PENDING_REQUESTS` | `1000` | Maximum concurrent requests |
| `IP_RATE_LIMIT` | `10` | Requests/second per IP |
| `IP_BURST_LIMIT` | `20` | Burst capacity per IP |
| `LIQUIDATION_SERVICE_URL` | `http://localhost:4001/liq/api/at-risk` | Liquidation service endpoint |
| `LIQUIDATION_INTERVAL_SECONDS` | `90` | Polling interval |
| `LIQUIDATION_ENABLED` | `true` | Enable liquidation polling |
| `ALLOWED_ORIGINS` | (none) | CORS allowed origins |
| `LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |
| `LOG_FORMAT` | `console` | Log format (json for production) |

## API Endpoints

### `GET /api/quote?th=PRICE`
Create a threshold price commitment.

**Response** (200 OK):
```json
{
  "chain_network": "bitcoin",
  "oracle_pubkey": "...",
  "base_price": 50000,
  "base_stamp": 1703289600,
  "commit_hash": "...",
  "contract_id": "...",
  "oracle_sig": "...",
  "thold_hash": "...",
  "thold_key": null,
  "thold_price": 49000
}
```

### `GET /api/price`
Get the latest cached BTC/USD price.

**Response** (200 OK):
```json
{
  "USD": 87202,
  "time": 1766771403
}
```

**Response** (503 Service Unavailable):
```json
{
  "error": "no price available",
  "message": "price data is stale or not yet received"
}
```

### `POST /webhook/ducat`
CRE callback endpoint for signed Nostr events.

### `POST /check`
Check if threshold breach occurred.

**Request Body**:
```json
{
  "domain": "req-123456789",
  "thold_hash": "abc123...def456"
}
```

### `GET /status/:request_id`
Poll request status for async operations.

### `GET /health`
Liveness probe.

### `GET /readiness`
Readiness probe with dependency checks.

### `GET /metrics`
Prometheus metrics endpoint.

## Building

```bash
cd gateway
go build -o gateway-server
```

## Running

```bash
export CRE_WORKFLOW_ID="your-workflow-id"
export DUCAT_AUTHORIZED_KEY="0x..."
export GATEWAY_CALLBACK_URL="https://your-server/webhook/ducat"
export DUCAT_PRIVATE_KEY="..."
export CRE_WEBHOOK_PUBKEY="..."

./gateway-server
```

## Testing

```bash
go test -v ./...
```

## Architecture

### Quote Flow

The gateway uses a tiered resolution strategy for quote requests:

```
GET /api/quote?th=95000
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│                    Quote Resolution                      │
│                                                         │
│  1. Calculate commit_hash locally                       │
│     commit_hash = hash340("DUCAT/commit",               │
│       oracle_pubkey || chain_network ||                 │
│       base_price || base_stamp || thold_price)          │
│                                                         │
│  2. Check local cache (5-min TTL)                       │
│     └── If found → return with collateral_ratio         │
│                                                         │
│  3. Query Nostr relay by d-tag (commit_hash)            │
│     GET /api/quotes?d=<commit_hash>                     │
│     └── If found → cache + return with collateral_ratio │
│                                                         │
│  4. Fallback to CRE (trigger workflow)                  │
│     └── Wait for webhook → return response              │
└─────────────────────────────────────────────────────────┘
```

### Request Flow

```
Client Request
     │
     ▼
┌─────────────────┐
│  Rate Limiter   │ ← Per-IP token bucket
└────────┬────────┘
         │
         ▼
┌─────────────────┐         ┌─────────────────┐
│ Request Handler │────────▶│   Quote Cache   │
└────────┬────────┘         │  (5-min TTL)    │
         │                  └────────┬────────┘
         │                           │
         │ (cache miss)              │
         ▼                           │
┌─────────────────┐                  │
│  Nostr Client   │────────────────▶ │
│  (HTTP fetch)   │ (cache on hit)   │
└────────┬────────┘                  │
         │                           │
         │ (not found)               │
         ▼                           │
┌─────────────────┐                  │
│ Circuit Breaker │                  │
└────────┬────────┘                  │
         │                           │
         ▼                           │
┌─────────────────┐    ┌─────────────────┐
│  CRE Gateway    │───▶│ Pending Request │
└────────┬────────┘    │     Registry    │
         │             └────────┬────────┘
         ▼                      │
┌─────────────────┐             │
│ Webhook Handler │ ◄───────────┘
│ (Signature      │
│  Verification)  │
└─────────────────┘
```

### Response Format

Quote responses now include `collateral_ratio`:

```json
{
  "chain_network": "mutinynet",
  "oracle_pubkey": "...",
  "base_price": 100000,
  "base_stamp": 1703289600,
  "commit_hash": "...",
  "contract_id": "...",
  "oracle_sig": "...",
  "thold_hash": "...",
  "thold_key": null,
  "thold_price": 135000,
  "collateral_ratio": 135.0
}
```

## Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `gateway_http_requests_total` | Counter | HTTP requests by endpoint/status |
| `gateway_http_request_duration_seconds` | Histogram | Request latency |
| `gateway_pending_requests` | Gauge | Current pending requests |
| `gateway_webhooks_received_total` | Counter | Webhooks by type/match status |
| `gateway_workflow_triggers_total` | Counter | Workflow triggers by status |
| `gateway_webhook_signature_failures_total` | Counter | Signature failures by reason |
| `gateway_rate_limit_rejected_total` | Counter | Rate-limited requests |
