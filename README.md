# DUCAT Oracle Gateway Server (Go)

A high-performance gateway server that bridges clients with the Chainlink CRE (Compute Runtime Environment) for privacy-preserving threshold price commitments.

## Overview

The gateway server handles:
- **Price Quote Creation**: Clients request threshold price commitments
- **Webhook Processing**: Receives signed responses from CRE
- **Liquidation Monitoring**: Polls at-risk vaults and triggers breach checks

## Security Features

- **BIP-340 Schnorr Signature Verification**: All webhooks verified against expected CRE public key
- **Constant-Time Comparisons**: Prevents timing attacks on sensitive comparisons
- **Replay Attack Prevention**: Event ID caching with automatic cleanup
- **Timestamp Validation**: Rejects stale/future webhooks (5-minute window, 5-second clock skew)
- **Rate Limiting**: Per-IP token bucket rate limiting
- **Circuit Breaker**: Prevents cascading failures to CRE gateway
- **Request Body Limits**: Prevents memory exhaustion attacks

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

```
Client Request
     │
     ▼
┌─────────────────┐
│  Rate Limiter   │ ← Per-IP token bucket
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Request Handler │
└────────┬────────┘
         │
         ├──────────────────────┐
         ▼                      ▼
┌─────────────────┐    ┌─────────────────┐
│ Circuit Breaker │    │ Pending Request │
└────────┬────────┘    │     Registry    │
         │             └────────┬────────┘
         ▼                      │
┌─────────────────┐             │
│  CRE Gateway    │             │
└────────┬────────┘             │
         │                      │
         ▼                      │
┌─────────────────┐             │
│ Webhook Handler │ ◄───────────┘
│ (Signature      │
│  Verification)  │
└─────────────────┘
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
