package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"gateway/internal/ethsign"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/time/rate"
)

// secureCompare performs constant-time string comparison to prevent timing attacks
func secureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// isValidHex validates that a string is valid hexadecimal of expected length
var hexRegex = regexp.MustCompile(`^[0-9a-fA-F]+$`)

func isValidHex(s string, expectedLen int) bool {
	if len(s) != expectedLen {
		return false
	}
	return hexRegex.MatchString(s)
}

// GatewayConfig holds all gateway server configuration
type GatewayConfig struct {
	WorkflowID      string
	GatewayURL      string
	AuthorizedKey   string
	CallbackURL     string
	BlockTimeout    time.Duration
	CleanupInterval time.Duration
	MaxPending      int

	// Rate limiting configuration (per-IP)
	IPRateLimit  rate.Limit // requests per second per IP
	IPBurstLimit int        // burst capacity per IP

	// Webhook security - expected CRE Schnorr public key (64 hex chars)
	// MANDATORY: webhooks must be signed by this key to be accepted
	ExpectedWebhookPubKey string

	// Liquidation service configuration
	LiquidationURL      string        // URL of the liquidation service endpoint
	LiquidationInterval time.Duration // How often to poll the liquidation service
	LiquidationEnabled  bool          // Whether to enable liquidation polling

	// Nostr relay configuration for quote lookup
	NostrRelayURL string // URL of the Nostr relay HTTP API
	OraclePubkey  string // Oracle's Schnorr public key for Nostr events (32 bytes hex)
	ChainNetwork  string // Chain network identifier (e.g., "mutiny", "mainnet")
}

// IPRateLimiter manages per-IP rate limiters with automatic cleanup
type IPRateLimiter struct {
	limiters map[string]*rateLimiterEntry
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
}

type rateLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewIPRateLimiter creates a new per-IP rate limiter
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	return &IPRateLimiter{
		limiters: make(map[string]*rateLimiterEntry),
		rate:     r,
		burst:    b,
	}
}

// Maximum number of IP rate limiters to prevent memory exhaustion DoS
const maxIPRateLimiters = 10000

// GetLimiter returns the rate limiter for the given IP, creating one if needed
// SECURITY: Enforces maximum map size to prevent memory exhaustion DoS
func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	entry, exists := i.limiters[ip]
	if !exists {
		// If at capacity, remove oldest entry first
		if len(i.limiters) >= maxIPRateLimiters {
			var oldestIP string
			var oldestTime time.Time
			for ip, entry := range i.limiters {
				if oldestIP == "" || entry.lastSeen.Before(oldestTime) {
					oldestIP = ip
					oldestTime = entry.lastSeen
				}
			}
			if oldestIP != "" {
				delete(i.limiters, oldestIP)
			}
		}

		limiter := rate.NewLimiter(i.rate, i.burst)
		i.limiters[ip] = &rateLimiterEntry{
			limiter:  limiter,
			lastSeen: time.Now(),
		}
		return limiter
	}

	entry.lastSeen = time.Now()
	return entry.limiter
}

// Cleanup removes rate limiters that haven't been used recently
func (i *IPRateLimiter) Cleanup(maxAge time.Duration) int {
	i.mu.Lock()
	defer i.mu.Unlock()

	now := time.Now()
	cleaned := 0
	for ip, entry := range i.limiters {
		if now.Sub(entry.lastSeen) > maxAge {
			delete(i.limiters, ip)
			cleaned++
		}
	}
	return cleaned
}

// CircuitBreaker implements a simple circuit breaker pattern to prevent cascading failures
type CircuitBreaker struct {
	mu              sync.RWMutex
	failures        int
	lastFailure     time.Time
	state           string // "closed", "open", "half-open"
	threshold       int    // failures before opening
	resetTimeout    time.Duration
	halfOpenMaxReqs int // max requests to try in half-open state
	halfOpenReqs    int
}

// NewCircuitBreaker creates a new circuit breaker with default settings
func NewCircuitBreaker(threshold int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		threshold:       threshold,
		resetTimeout:    resetTimeout,
		state:           "closed",
		halfOpenMaxReqs: 3,
	}
}

// Allow checks if a request should be allowed through
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case "closed":
		return true
	case "open":
		// Check if we should transition to half-open
		if time.Since(cb.lastFailure) > cb.resetTimeout {
			cb.state = "half-open"
			cb.halfOpenReqs = 0
			return true
		}
		return false
	case "half-open":
		// Allow limited requests in half-open state
		if cb.halfOpenReqs < cb.halfOpenMaxReqs {
			cb.halfOpenReqs++
			return true
		}
		return false
	}
	return false
}

// RecordSuccess records a successful request
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == "half-open" {
		// Reset on success in half-open state
		cb.state = "closed"
		cb.failures = 0
	}
}

// RecordFailure records a failed request
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFailure = time.Now()

	if cb.state == "half-open" || cb.failures >= cb.threshold {
		cb.state = "open"
	}
}

// State returns the current circuit breaker state
func (cb *CircuitBreaker) State() string {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// webhookCacheTTL is how long processed webhook event IDs are cached (5 minutes)
const webhookCacheTTL = 5 * time.Minute

// GatewayServer encapsulates all server state
type GatewayServer struct {
	config          *GatewayConfig
	privateKey      *ecdsa.PrivateKey
	logger          *zap.Logger
	pendingRequests map[string]*PendingRequest
	requestsMutex   sync.RWMutex
	shutdownChan    chan struct{}
	ipRateLimiter   *IPRateLimiter
	circuitBreaker  *CircuitBreaker
	// Replay protection: maps event_id -> timestamp
	processedWebhooks      map[string]time.Time
	processedWebhooksMutex sync.RWMutex
	// Quote caching for new flow
	quoteCache  *QuoteCache
	nostrClient *NostrClient
}

// isWebhookReplayed checks if a webhook has already been processed (replay attack prevention)
func (s *GatewayServer) isWebhookReplayed(eventID string) bool {
	s.processedWebhooksMutex.RLock()
	defer s.processedWebhooksMutex.RUnlock()
	_, exists := s.processedWebhooks[eventID]
	return exists
}

// Maximum webhook cache size to prevent memory exhaustion DoS
const maxWebhookCacheSize = 10000

// markWebhookProcessed records that a webhook has been processed
// SECURITY: Enforces maximum cache size to prevent memory exhaustion DoS
func (s *GatewayServer) markWebhookProcessed(eventID string) {
	s.processedWebhooksMutex.Lock()
	defer s.processedWebhooksMutex.Unlock()

	// If at capacity, remove oldest entries first (simple eviction)
	if len(s.processedWebhooks) >= maxWebhookCacheSize {
		// Find and remove oldest entry
		var oldestKey string
		var oldestTime time.Time
		for k, v := range s.processedWebhooks {
			if oldestKey == "" || v.Before(oldestTime) {
				oldestKey = k
				oldestTime = v
			}
		}
		if oldestKey != "" {
			delete(s.processedWebhooks, oldestKey)
		}
	}
	s.processedWebhooks[eventID] = time.Now()
}

// cleanupWebhookCache removes old webhook entries from the replay protection cache
func (s *GatewayServer) cleanupWebhookCache() int {
	s.processedWebhooksMutex.Lock()
	defer s.processedWebhooksMutex.Unlock()

	now := time.Now()
	cleaned := 0
	for eventID, ts := range s.processedWebhooks {
		if now.Sub(ts) > webhookCacheTTL {
			delete(s.processedWebhooks, eventID)
			cleaned++
		}
	}
	return cleaned
}

// cacheWebhookPrice extracts price data from a webhook and caches it for quote lookups.
// This enables the new flow where quotes can be served from cache + Nostr without CRE calls.
func (s *GatewayServer) cacheWebhookPrice(payload *WebhookPayload) {
	if payload == nil || payload.Content == "" {
		return
	}

	// Try to parse as PriceContractResponse
	var priceContract PriceContractResponse
	if err := json.Unmarshal([]byte(payload.Content), &priceContract); err != nil {
		s.logger.Debug("Could not parse webhook content as price contract (ignoring)",
			zap.Error(err),
		)
		return
	}

	// Only cache if we have valid price data
	if priceContract.BasePrice <= 0 || priceContract.BaseStamp <= 0 {
		s.logger.Debug("Invalid price data in webhook (ignoring)",
			zap.Int64("base_price", priceContract.BasePrice),
			zap.Int64("base_stamp", priceContract.BaseStamp),
		)
		return
	}

	// Update the price cache
	s.quoteCache.SetPrice(uint32(priceContract.BasePrice), uint32(priceContract.BaseStamp))
	s.logger.Debug("Cached price from webhook",
		zap.Int64("base_price", priceContract.BasePrice),
		zap.Int64("base_stamp", priceContract.BaseStamp),
	)

	// Also cache the full quote if we have a commit_hash
	if priceContract.CommitHash != "" {
		s.quoteCache.SetQuote(priceContract.CommitHash, &priceContract)
		s.logger.Debug("Cached quote from webhook",
			zap.String("commit_hash", priceContract.CommitHash),
		)
	}
}

// Request tracking
type PendingRequest struct {
	RequestID  string
	CreatedAt  time.Time
	ResultChan chan *WebhookPayload
	Status     string // "pending", "completed", "timeout"
	Result     *WebhookPayload
	TimedOut   bool
}

// Global server instance (initialized in init)
var (
	server *GatewayServer
	logger *zap.Logger
)

// Prometheus metrics
var (
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_http_requests_total",
			Help: "Total number of HTTP requests by endpoint and status",
		},
		[]string{"endpoint", "method", "status"},
	)

	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "gateway_http_request_duration_seconds",
			Help:    "HTTP request latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"endpoint", "method"},
	)

	pendingRequestsGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "gateway_pending_requests",
			Help: "Current number of pending requests",
		},
	)

	webhooksReceived = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_webhooks_received_total",
			Help: "Total number of webhooks received by event type",
		},
		[]string{"event_type", "matched"},
	)

	workflowTriggers = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_workflow_triggers_total",
			Help: "Total number of workflow triggers by operation and status",
		},
		[]string{"operation", "status"},
	)

	requestsCleanedUp = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "gateway_requests_cleaned_up_total",
			Help: "Total number of old requests cleaned up",
		},
	)

	requestTimeouts = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_request_timeouts_total",
			Help: "Total number of request timeouts by endpoint",
		},
		[]string{"endpoint"},
	)

	healthChecks = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_health_checks_total",
			Help: "Total number of health/readiness checks by status",
		},
		[]string{"type", "status"},
	)

	dependencyStatus = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gateway_dependency_status",
			Help: "Status of dependencies (1=up, 0.5=degraded, 0=down)",
		},
		[]string{"dependency"},
	)

	rateLimitRejected = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_rate_limit_rejected_total",
			Help: "Total number of requests rejected due to rate limiting",
		},
		[]string{"endpoint"},
	)

	panicsRecovered = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "gateway_panics_recovered_total",
			Help: "Total number of panics recovered by the server",
		},
	)

	webhookSignatureFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_webhook_signature_failures_total",
			Help: "Total number of webhook signature verification failures",
		},
		[]string{"reason"},
	)
)

// validatePrivateKey validates that a hex-encoded private key is exactly 32 bytes
// and falls within the valid range for secp256k1 (1 < key < curve order).
func validatePrivateKey(hexKey string) error {
	if len(hexKey) != 64 {
		return fmt.Errorf("private key must be 64 hex chars, got %d", len(hexKey))
	}

	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return fmt.Errorf("invalid hex encoding: %w", err)
	}

	// Check key is in valid range (0 < key < curve order)
	keyInt := new(big.Int).SetBytes(keyBytes)
	curveOrder := btcec.S256().Params().N

	if keyInt.Sign() == 0 {
		return fmt.Errorf("private key cannot be zero")
	}
	if keyInt.Cmp(curveOrder) >= 0 {
		return fmt.Errorf("private key exceeds curve order")
	}

	return nil
}

// verifyWebhookSignature verifies that a webhook payload has a valid Nostr event signature.
// This validates that the webhook actually came from the CRE and hasn't been tampered with.
// The event ID must be the SHA256 hash of the canonical serialized event, and the signature
// must be a valid BIP-340 Schnorr signature over the event ID using the event's public key.
//
// SECURITY: This prevents attackers from injecting fake webhook payloads to spoof
// price contract responses. Without this verification, an attacker could send arbitrary
// webhooks to manipulate oracle responses.
func verifyWebhookSignature(payload *WebhookPayload) error {
	if payload == nil {
		return fmt.Errorf("payload cannot be nil")
	}

	// Validate required fields
	if payload.EventID == "" {
		return fmt.Errorf("missing event_id")
	}
	if payload.PubKey == "" {
		return fmt.Errorf("missing pubkey")
	}
	if payload.Sig == "" {
		return fmt.Errorf("missing signature")
	}

	// Validate field lengths
	if len(payload.EventID) != 64 {
		return fmt.Errorf("invalid event_id length: expected 64 hex chars, got %d", len(payload.EventID))
	}
	if len(payload.PubKey) != 64 {
		return fmt.Errorf("invalid pubkey length: expected 64 hex chars, got %d", len(payload.PubKey))
	}
	if len(payload.Sig) != 128 {
		return fmt.Errorf("invalid signature length: expected 128 hex chars, got %d", len(payload.Sig))
	}

	// SECURITY: Validate tags array size to prevent memory exhaustion DoS
	const maxTags = 100
	const maxTagElements = 10
	const maxTagElementLen = 1024
	if len(payload.Tags) > maxTags {
		return fmt.Errorf("too many tags: max %d, got %d", maxTags, len(payload.Tags))
	}
	for i, tag := range payload.Tags {
		if len(tag) > maxTagElements {
			return fmt.Errorf("tag %d has too many elements: max %d, got %d", i, maxTagElements, len(tag))
		}
		for j, elem := range tag {
			if len(elem) > maxTagElementLen {
				return fmt.Errorf("tag %d element %d too long: max %d, got %d", i, j, maxTagElementLen, len(elem))
			}
		}
	}

	// Recompute event ID to verify integrity
	// NIP-01 format: [0, <pubkey>, <created_at>, <kind>, <tags>, <content>]
	tagsJSON, err := json.Marshal(payload.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}
	serialized := fmt.Sprintf("[0,%q,%d,%d,%s,%q]",
		payload.PubKey, payload.CreatedAt, payload.Kind, string(tagsJSON), payload.Content)

	computedHash := sha256.Sum256([]byte(serialized))
	computedID := hex.EncodeToString(computedHash[:])

	if computedID != payload.EventID {
		return fmt.Errorf("event_id mismatch: computed %s, got %s", computedID, payload.EventID)
	}

	// Decode and verify Schnorr signature
	sigBytes, err := hex.DecodeString(payload.Sig)
	if err != nil {
		return fmt.Errorf("invalid signature hex: %w", err)
	}

	// SECURITY: Reject all-zero signatures to prevent potential bypass attacks
	isZero := true
	for _, b := range sigBytes {
		if b != 0 {
			isZero = false
			break
		}
	}
	if isZero {
		return fmt.Errorf("invalid signature: all-zero signature rejected")
	}

	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("invalid schnorr signature format: %w", err)
	}

	pubKeyBytes, err := hex.DecodeString(payload.PubKey)
	if err != nil {
		return fmt.Errorf("invalid pubkey hex: %w", err)
	}

	// SECURITY: Reject all-zero pubkeys to prevent point-at-infinity attacks
	isZeroPubKey := true
	for _, b := range pubKeyBytes {
		if b != 0 {
			isZeroPubKey = false
			break
		}
	}
	if isZeroPubKey {
		return fmt.Errorf("invalid pubkey: all-zero pubkey rejected")
	}

	pubKey, err := schnorr.ParsePubKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("invalid schnorr pubkey: %w", err)
	}

	eventIDBytes, err := hex.DecodeString(payload.EventID)
	if err != nil {
		return fmt.Errorf("invalid event_id hex: %w", err)
	}

	if !sig.Verify(eventIDBytes, pubKey) {
		return fmt.Errorf("schnorr signature verification failed")
	}

	return nil
}

// panicRecoveryMiddleware catches panics in HTTP handlers and logs them.
func panicRecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				panicsRecovered.Inc()
				if logger != nil {
					logger.Error("panic recovered in HTTP handler",
						zap.Any("error", err),
						zap.String("path", r.URL.Path),
						zap.String("method", r.Method),
						zap.String("stack", string(debug.Stack())),
					)
				} else {
					log.Printf("PANIC: %v\nStack: %s", err, debug.Stack())
				}
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Client request types
type CreateRequest struct {
	Th     float64 `json:"th"`
	Domain string  `json:"domain,omitempty"`
}

type CheckRequest struct {
	Domain    string `json:"domain"`
	TholdHash string `json:"thold_hash"`
}

// Webhook payload from CRE
type WebhookPayload struct {
	EventType  string                 `json:"event_type"`
	EventID    string                 `json:"event_id"`
	PubKey     string                 `json:"pubkey"`
	CreatedAt  int64                  `json:"created_at"`
	Kind       int                    `json:"kind"`
	Tags       [][]string             `json:"tags"`
	Content    string                 `json:"content"`
	Sig        string                 `json:"sig"`
	NostrEvent map[string]interface{} `json:"nostr_event"`
}

// PriceQuote matches Rust protocol-sdk v3 schema (ducat-protocol/src/oracle.rs)
// This is the format used by validator-rs and protocol-sdk
// NOTE: Prices are float64 to match cre-hmac which uses float64 for HMAC computation
type PriceQuote struct {
	// Server identity
	SrvNetwork string `json:"srv_network"` // Network: main, test, regtest, signet, mutinynet
	SrvPubkey  string `json:"srv_pubkey"`  // Oracle's compressed secp256k1 public key (33 bytes hex)

	// Quote creation data
	QuoteOrigin string  `json:"quote_origin"` // Price source: gecko, generator
	QuotePrice  float64 `json:"quote_price"`  // BTC/USD price at quote creation
	QuoteStamp  int64   `json:"quote_stamp"`  // Unix timestamp of quote creation

	// Latest price data
	LatestOrigin string  `json:"latest_origin"` // Source of latest price
	LatestPrice  float64 `json:"latest_price"`  // Current BTC/USD price
	LatestStamp  int64   `json:"latest_stamp"`  // Timestamp of latest price

	// Event/breach data (optional, populated when threshold crossed)
	EventOrigin *string  `json:"event_origin,omitempty"` // Data source when threshold crossed
	EventPrice  *float64 `json:"event_price,omitempty"`  // Price when threshold was first crossed
	EventStamp  *int64   `json:"event_stamp,omitempty"`  // Timestamp when threshold crossed
	EventType   *string  `json:"event_type,omitempty"`   // Type: none, price_drop, price_rise, breach, crash, shock

	// Threshold commitment
	TholdHash  string   `json:"thold_hash"`           // Hash160 commitment - 20 bytes hex
	TholdPrice float64  `json:"thold_price"`          // Threshold price
	TholdKey   *string  `json:"thold_key,omitempty"`  // Secret revealed on breach - 32 bytes hex
	IsExpired  bool     `json:"is_expired"`           // Whether threshold was breached

	// Request identification
	ReqID  *string `json:"req_id,omitempty"`  // Request ID hash - 32 bytes hex
	ReqSig *string `json:"req_sig,omitempty"` // Request signature - 64 bytes hex
}

// PriceContractResponse is the internal CRE format
// Used for backward compatibility with CRE webhook responses
type PriceContractResponse struct {
	ChainNetwork string  `json:"chain_network"` // Bitcoin network
	OraclePubkey string  `json:"oracle_pubkey"` // Server Schnorr public key (32 bytes hex)
	BasePrice    float64 `json:"base_price"`    // Quote creation price
	BaseStamp    int64   `json:"base_stamp"`    // Quote creation timestamp
	CommitHash   string  `json:"commit_hash"`   // hash340(tag, preimage) - 32 bytes hex
	ContractID   string  `json:"contract_id"`   // hash340(tag, commit||thold) - 32 bytes hex
	OracleSig    string  `json:"oracle_sig"`    // Schnorr signature - 64 bytes hex
	TholdHash    string  `json:"thold_hash"`    // Hash160 commitment - 20 bytes hex
	TholdKey     *string `json:"thold_key"`     // Secret (null if sealed) - 32 bytes hex
	TholdPrice   float64 `json:"thold_price"`   // Threshold price
}

// ToV3Quote converts internal CRE format to v3 protocol-sdk format
func (p *PriceContractResponse) ToV3Quote() *PriceQuote {
	isExpired := p.TholdKey != nil
	var eventPrice *float64
	var eventStamp *int64
	var eventOrigin, eventType *string
	if isExpired {
		eventPrice = &p.BasePrice
		eventStamp = &p.BaseStamp
		origin := "cre"
		eventOrigin = &origin
		breach := "breach"
		eventType = &breach
	}
	return &PriceQuote{
		SrvNetwork:   p.ChainNetwork,
		SrvPubkey:    p.OraclePubkey,
		QuoteOrigin:  "cre",
		QuotePrice:   p.BasePrice,
		QuoteStamp:   p.BaseStamp,
		LatestOrigin: "cre",
		LatestPrice:  p.BasePrice,
		LatestStamp:  p.BaseStamp,
		EventOrigin:  eventOrigin,
		EventPrice:   eventPrice,
		EventStamp:   eventStamp,
		EventType:    eventType,
		TholdHash:    p.TholdHash,
		TholdPrice:   p.TholdPrice,
		TholdKey:     p.TholdKey,
		IsExpired:    isExpired,
		ReqID:        &p.CommitHash,
		ReqSig:       &p.OracleSig,
	}
}

// QuoteResponse extends PriceQuote with collateral ratio for frontend
type QuoteResponse struct {
	PriceQuote
	CollateralRatio float64 `json:"collateral_ratio"` // Collateral ratio as percentage (e.g., 135.0 for 135%)
}

// Response types
type SyncResponse struct {
	Status    string                 `json:"status"` // "completed", "timeout"
	RequestID string                 `json:"request_id"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Result    *WebhookPayload        `json:"result,omitempty"`
	Message   string                 `json:"message,omitempty"`
}

func init() {
	// Initialize structured logger
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
	}

	var zapConfig zap.Config
	if os.Getenv("LOG_FORMAT") == "json" {
		zapConfig = zap.NewProductionConfig()
	} else {
		zapConfig = zap.NewDevelopmentConfig()
		zapConfig.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	// Parse log level
	level, err := zapcore.ParseLevel(logLevel)
	if err != nil {
		level = zapcore.InfoLevel
	}
	zapConfig.Level = zap.NewAtomicLevelAt(level)

	logger, err = zapConfig.Build()
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	// Load configuration into struct
	config := loadConfig()

	// Load and validate private key from environment variable
	privateKeyHex := os.Getenv("DUCAT_PRIVATE_KEY")
	if privateKeyHex == "" {
		logger.Fatal("DUCAT_PRIVATE_KEY environment variable not set")
	}

	privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")

	// Validate private key format and range before use
	if err := validatePrivateKey(privateKeyHex); err != nil {
		logger.Fatal("Invalid private key", zap.Error(err))
	}

	privKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		logger.Fatal("Failed to decode private key", zap.Error(err))
	}

	privateKey, err := crypto.ToECDSA(privKeyBytes)
	if err != nil {
		logger.Fatal("Failed to parse private key", zap.Error(err))
	}

	// Initialize server with config
	// Circuit breaker: 5 failures opens circuit, 30 second reset timeout
	server = &GatewayServer{
		config:            config,
		privateKey:        privateKey,
		logger:            logger,
		pendingRequests:   make(map[string]*PendingRequest),
		shutdownChan:      make(chan struct{}),
		ipRateLimiter:     NewIPRateLimiter(config.IPRateLimit, config.IPBurstLimit),
		circuitBreaker:    NewCircuitBreaker(5, 30*time.Second),
		processedWebhooks: make(map[string]time.Time),
		quoteCache:        NewQuoteCache(),
		nostrClient:       NewNostrClient(config.NostrRelayURL, config.OraclePubkey, logger),
	}

	logger.Info("Gateway server initialized",
		zap.String("authorized_key", config.AuthorizedKey),
		zap.String("callback_url", config.CallbackURL),
		zap.Int("max_pending", config.MaxPending),
		zap.Duration("block_timeout", config.BlockTimeout),
		zap.String("workflow_id", config.WorkflowID),
		zap.Float64("ip_rate_limit", float64(config.IPRateLimit)),
		zap.Int("ip_burst_limit", config.IPBurstLimit),
		zap.Bool("liquidation_enabled", config.LiquidationEnabled),
		zap.String("liquidation_url", config.LiquidationURL),
		zap.Duration("liquidation_interval", config.LiquidationInterval),
		zap.String("nostr_relay_url", config.NostrRelayURL),
		zap.String("chain_network", config.ChainNetwork),
	)

	// Start cleanup goroutine
	go server.cleanupOldRequests()

	// Start liquidation poller if enabled
	if config.LiquidationEnabled {
		go server.pollLiquidationService()
	}
}

func loadConfig() *GatewayConfig {
	// Use basic log for config errors since logger might not be initialized yet
	logFatal := func(msg string, args ...interface{}) {
		if logger != nil {
			logger.Fatal(msg)
		} else {
			log.Fatalf(msg, args...)
		}
	}

	logWarn := func(msg string, args ...interface{}) {
		if logger != nil {
			logger.Warn(msg)
		} else {
			log.Printf("WARNING: "+msg, args...)
		}
	}

	config := &GatewayConfig{}

	// Required configuration
	config.WorkflowID = os.Getenv("CRE_WORKFLOW_ID")
	if config.WorkflowID == "" {
		logFatal("CRE_WORKFLOW_ID environment variable not set")
	}

	config.GatewayURL = os.Getenv("CRE_GATEWAY_URL")
	if config.GatewayURL == "" {
		config.GatewayURL = "https://01.gateway.zone-a.cre.chain.link" // Default
		logWarn("CRE_GATEWAY_URL not set, using default: " + config.GatewayURL)
	}

	config.AuthorizedKey = os.Getenv("DUCAT_AUTHORIZED_KEY")
	if config.AuthorizedKey == "" {
		logFatal("DUCAT_AUTHORIZED_KEY environment variable not set")
	}

	config.CallbackURL = os.Getenv("GATEWAY_CALLBACK_URL")
	if config.CallbackURL == "" {
		logFatal("GATEWAY_CALLBACK_URL environment variable not set")
	}

	// Optional configuration with defaults
	blockTimeoutStr := os.Getenv("BLOCK_TIMEOUT_SECONDS")
	if blockTimeoutStr == "" {
		config.BlockTimeout = 60 * time.Second
	} else {
		var seconds int
		if _, err := fmt.Sscanf(blockTimeoutStr, "%d", &seconds); err != nil {
			logFatal("Invalid BLOCK_TIMEOUT_SECONDS: %v", err)
		}
		config.BlockTimeout = time.Duration(seconds) * time.Second
	}

	cleanupIntervalStr := os.Getenv("CLEANUP_INTERVAL_SECONDS")
	if cleanupIntervalStr == "" {
		config.CleanupInterval = 2 * time.Minute
	} else {
		var seconds int
		if _, err := fmt.Sscanf(cleanupIntervalStr, "%d", &seconds); err != nil {
			logFatal("Invalid CLEANUP_INTERVAL_SECONDS: %v", err)
		}
		config.CleanupInterval = time.Duration(seconds) * time.Second
	}

	maxPendingStr := os.Getenv("MAX_PENDING_REQUESTS")
	if maxPendingStr == "" {
		config.MaxPending = 1000
	} else {
		if _, err := fmt.Sscanf(maxPendingStr, "%d", &config.MaxPending); err != nil {
			logFatal("Invalid MAX_PENDING_REQUESTS: %v", err)
		}
	}

	// Per-IP rate limiting configuration
	// Default: 10 requests/second per IP with burst of 20
	// This prevents individual IPs from overwhelming the service
	ipRateLimitStr := os.Getenv("IP_RATE_LIMIT")
	if ipRateLimitStr == "" {
		config.IPRateLimit = 10 // 10 req/sec per IP
	} else {
		var rateLimit float64
		if _, err := fmt.Sscanf(ipRateLimitStr, "%f", &rateLimit); err != nil {
			logFatal("Invalid IP_RATE_LIMIT: %v", err)
		}
		config.IPRateLimit = rate.Limit(rateLimit)
	}

	ipBurstStr := os.Getenv("IP_BURST_LIMIT")
	if ipBurstStr == "" {
		config.IPBurstLimit = 20 // burst of 20 per IP
	} else {
		if _, err := fmt.Sscanf(ipBurstStr, "%d", &config.IPBurstLimit); err != nil {
			logFatal("Invalid IP_BURST_LIMIT: %v", err)
		}
	}

	// SECURITY: Expected CRE public key for webhook signature validation
	// MANDATORY in production: Webhooks MUST be signed by this key to be accepted
	config.ExpectedWebhookPubKey = os.Getenv("CRE_WEBHOOK_PUBKEY")
	if config.ExpectedWebhookPubKey == "" {
		// Allow unset only when running tests (GO_TEST environment is set by go test)
		if os.Getenv("GO_TEST") != "1" && !strings.HasSuffix(os.Args[0], ".test") {
			logFatal("CRE_WEBHOOK_PUBKEY is REQUIRED - webhooks must be signed by a known CRE public key")
		}
		// For tests, use the pubkey derived from testWebhookPrivKey ("aa...aa")
		// This matches the test private key in gateway_server_test.go
		config.ExpectedWebhookPubKey = "6a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3"
		logWarn("CRE_WEBHOOK_PUBKEY not set - using test dummy (only valid in test mode)")
	} else {
		// Validate format: must be exactly 64 lowercase hex characters
		if len(config.ExpectedWebhookPubKey) != 64 {
			logFatal("CRE_WEBHOOK_PUBKEY must be 64 hex characters (32 bytes), got %d", len(config.ExpectedWebhookPubKey))
		}
		if _, err := hex.DecodeString(config.ExpectedWebhookPubKey); err != nil {
			logFatal("CRE_WEBHOOK_PUBKEY invalid hex: %v", err)
		}
	}

	// Liquidation service configuration
	config.LiquidationURL = os.Getenv("LIQUIDATION_SERVICE_URL")
	if config.LiquidationURL == "" {
		config.LiquidationURL = "http://localhost:4001/liq/api/at-risk"
	}

	// Liquidation polling interval (default: 90 seconds / 1.5 minutes)
	liquidationIntervalStr := os.Getenv("LIQUIDATION_INTERVAL_SECONDS")
	if liquidationIntervalStr == "" {
		config.LiquidationInterval = 90 * time.Second
	} else {
		var seconds int
		if _, err := fmt.Sscanf(liquidationIntervalStr, "%d", &seconds); err != nil {
			logFatal("Invalid LIQUIDATION_INTERVAL_SECONDS: %v", err)
		}
		config.LiquidationInterval = time.Duration(seconds) * time.Second
	}

	// Enable liquidation polling (default: true if URL is set)
	liquidationEnabled := os.Getenv("LIQUIDATION_ENABLED")
	if liquidationEnabled == "" {
		config.LiquidationEnabled = true // Enabled by default
	} else {
		config.LiquidationEnabled = liquidationEnabled == "true" || liquidationEnabled == "1"
	}

	// Nostr relay configuration for quote lookup
	config.NostrRelayURL = os.Getenv("NOSTR_RELAY_URL")
	if config.NostrRelayURL == "" {
		config.NostrRelayURL = "https://relay.ducat.dev" // Default
	}

	config.OraclePubkey = os.Getenv("ORACLE_PUBKEY")
	if config.OraclePubkey == "" {
		// In production, this should be set - use test default for development
		config.OraclePubkey = "0000000000000000000000000000000000000000000000000000000000000000"
		logWarn("ORACLE_PUBKEY not set - using test default")
	} else {
		// Validate format: must be exactly 64 hex characters
		if len(config.OraclePubkey) != 64 {
			logFatal("ORACLE_PUBKEY must be 64 hex characters (32 bytes), got %d", len(config.OraclePubkey))
		}
		if _, err := hex.DecodeString(config.OraclePubkey); err != nil {
			logFatal("ORACLE_PUBKEY invalid hex: %v", err)
		}
	}

	config.ChainNetwork = os.Getenv("CHAIN_NETWORK")
	if config.ChainNetwork == "" {
		config.ChainNetwork = "mutiny" // Default to mutiny testnet
	}

	return config
}

func main() {
	defer logger.Sync()

	// Wrap all handlers with panic recovery and metrics middleware
	// Rate limiting applied to both /api/quote and /webhook/ducat to prevent DoS
	http.Handle("/api/quote", panicRecoveryMiddleware(
		metricsMiddleware("create", server.rateLimitMiddleware(http.HandlerFunc(server.handleCreate)))))
	http.Handle("/webhook/ducat", panicRecoveryMiddleware(
		metricsMiddleware("webhook", server.rateLimitMiddleware(http.HandlerFunc(server.handleWebhook)))))
	http.Handle("/health", panicRecoveryMiddleware(http.HandlerFunc(handleHealth)))
	http.Handle("/readiness", panicRecoveryMiddleware(http.HandlerFunc(server.handleReadiness)))
	http.Handle("/metrics", promhttp.Handler())

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	port = ":" + strings.TrimPrefix(port, ":")

	logger.Info("DUCAT Blocking Gateway Server starting",
		zap.String("port", port),
		zap.Duration("block_timeout", server.config.BlockTimeout),
		zap.Int("max_pending", server.config.MaxPending),
	)

	logger.Info("Endpoints registered",
		zap.Strings("endpoints", []string{
			"GET /api/quote?th=PRICE - Create threshold commitment",
			"POST /webhook/ducat - CRE callback endpoint",
			"GET /health - Liveness probe (simple health check)",
			"GET /readiness - Readiness probe (dependency checks)",
			"GET /metrics - Prometheus metrics",
		}),
	)

	// Create HTTP server for graceful shutdown
	httpServer := &http.Server{
		Addr:         port,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: server.config.BlockTimeout + 10*time.Second, // Allow for blocking requests
		IdleTimeout:  120 * time.Second,
	}

	// Channel to signal server shutdown complete
	serverDone := make(chan struct{})

	// Start server in goroutine
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Server failed", zap.Error(err))
		}
		close(serverDone)
	}()

	// Wait for interrupt signal for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan

	logger.Info("Received shutdown signal", zap.String("signal", sig.String()))

	// Signal cleanup goroutine to stop
	close(server.shutdownChan)

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Gracefully shutdown HTTP server
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("Server shutdown error", zap.Error(err))
	}

	// Wait for server to finish
	<-serverDone

	logger.Info("Server shutdown complete")
}

// metricsMiddleware wraps HTTP handlers with request metrics
func metricsMiddleware(endpoint string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap ResponseWriter to capture status code
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rw, r)

		duration := time.Since(start).Seconds()
		status := fmt.Sprintf("%d", rw.statusCode)

		httpRequestsTotal.WithLabelValues(endpoint, r.Method, status).Inc()
		httpRequestDuration.WithLabelValues(endpoint, r.Method).Observe(duration)
	})
}

// getClientIP extracts the real client IP, handling X-Forwarded-For header
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (for reverse proxies)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Take the first IP in the chain (original client)
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if ip != "" {
				return ip
			}
		}
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr (strip port)
	ip := r.RemoteAddr
	if colonIdx := strings.LastIndex(ip, ":"); colonIdx != -1 {
		ip = ip[:colonIdx]
	}
	return ip
}

// rateLimitMiddleware applies per-IP token bucket rate limiting to protect against DoS attacks.
// Returns 429 Too Many Requests if the rate limit is exceeded for the client's IP.
func (s *GatewayServer) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		limiter := s.ipRateLimiter.GetLimiter(clientIP)

		if !limiter.Allow() {
			rateLimitRejected.WithLabelValues(r.URL.Path).Inc()
			s.logger.Warn("Per-IP rate limit exceeded",
				zap.String("client_ip", clientIP),
				zap.String("endpoint", r.URL.Path),
			)
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// handleCreate handles GET /api/quote?th=PRICE requests using the new flow:
// 1. Get cached price data from webhooks
// 2. Calculate commit_hash locally (d-tag)
// 3. Try local cache first
// 4. Try Nostr relay lookup
// 5. Fall back to CRE workflow if quote not found
//
// This flow is optimized for serving pre-baked quotes from Nostr, avoiding CRE calls
// when possible. The response includes collateral_ratio calculated from prices.
//
// Observed HTTP behaviors:
//   - 200: successful quote response with collateral_ratio.
//   - 202: request timed out waiting for CRE (fallback path).
//   - 400: missing or invalid `th` parameter.
//   - 405: method not allowed (only GET and OPTIONS supported).
//   - 500: internal error (no cached price, calculation failure, etc).
//   - 503: server at capacity (too many pending requests).
func (s *GatewayServer) handleCreate(w http.ResponseWriter, r *http.Request) {
	// Set restrictive CORS headers - only allow configured origins
	// For production, configure ALLOWED_ORIGINS environment variable
	allowedOrigin := os.Getenv("ALLOWED_ORIGINS")
	if allowedOrigin == "" {
		// Default: no CORS (same-origin only)
		// In development, you can set ALLOWED_ORIGINS=* but this is NOT recommended for production
	} else {
		w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	// Handle preflight
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse query parameter
	thStr := r.URL.Query().Get("th")
	if thStr == "" {
		http.Error(w, "Missing th query parameter", http.StatusBadRequest)
		return
	}

	// Parse threshold price
	var th float64
	if _, err := fmt.Sscanf(thStr, "%f", &th); err != nil {
		http.Error(w, "Invalid th value", http.StatusBadRequest)
		return
	}

	// Validate request
	if th <= 0 {
		http.Error(w, "Invalid th (threshold price must be positive)", http.StatusBadRequest)
		return
	}

	tholdPrice := uint32(th)

	// Step 1: Get cached price data
	cachedPrice := s.quoteCache.GetPrice()
	if cachedPrice == nil {
		s.logger.Warn("No cached price data available, falling back to CRE")
		s.fallbackToCRE(w, th)
		return
	}

	s.logger.Debug("Using cached price",
		zap.Uint32("base_price", cachedPrice.BasePrice),
		zap.Uint32("base_stamp", cachedPrice.BaseStamp),
	)

	// Step 2: Calculate commit_hash locally (d-tag for Nostr lookup)
	commitHash, err := CalculateCommitHash(
		s.config.OraclePubkey,
		s.config.ChainNetwork,
		cachedPrice.BasePrice,
		cachedPrice.BaseStamp,
		tholdPrice,
	)
	if err != nil {
		s.logger.Error("Failed to calculate commit_hash",
			zap.Error(err),
		)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	s.logger.Debug("Calculated commit_hash",
		zap.String("commit_hash", commitHash),
		zap.Uint32("thold_price", tholdPrice),
	)

	// Step 3: Try local cache first
	if quote := s.quoteCache.GetQuote(commitHash); quote != nil {
		s.logger.Info("Quote served from local cache",
			zap.String("commit_hash", commitHash),
		)
		collateralRatio := CalculateCollateralRatio(cachedPrice.BasePrice, tholdPrice)
		s.sendQuoteResponse(w, quote, collateralRatio)
		return
	}

	// Step 4: Try Nostr relay lookup
	quote, err := s.nostrClient.FetchQuoteByDTag(commitHash)
	if err != nil {
		s.logger.Warn("Failed to fetch quote from Nostr relay",
			zap.String("commit_hash", commitHash),
			zap.Error(err),
		)
		// Fall through to CRE fallback
	} else if quote != nil {
		// Found in Nostr! Cache it and return
		s.quoteCache.SetQuote(commitHash, quote)
		s.logger.Info("Quote served from Nostr relay",
			zap.String("commit_hash", commitHash),
		)
		collateralRatio := CalculateCollateralRatio(cachedPrice.BasePrice, tholdPrice)
		s.sendQuoteResponse(w, quote, collateralRatio)
		return
	}

	// Step 5: Fall back to CRE workflow
	s.logger.Info("Quote not found in cache or Nostr, falling back to CRE",
		zap.String("commit_hash", commitHash),
	)
	s.fallbackToCRE(w, th)
}

// sendQuoteResponse sends a QuoteResponse with the given price contract and collateral ratio
func (s *GatewayServer) sendQuoteResponse(w http.ResponseWriter, quote *PriceContractResponse, collateralRatio float64) {
	// Convert internal CRE format to v3 protocol-sdk format
	v3Quote := quote.ToV3Quote()
	response := QuoteResponse{
		PriceQuote:      *v3Quote,
		CollateralRatio: collateralRatio,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// fallbackToCRE triggers the CRE workflow and blocks waiting for response
func (s *GatewayServer) fallbackToCRE(w http.ResponseWriter, th float64) {
	// Generate domain with cryptographically random component to prevent prediction attacks
	// An attacker who can predict domains could pre-send forged webhooks
	randomID, err := ethsign.GenerateRequestID()
	if err != nil {
		s.logger.Error("Failed to generate random ID", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	// Use 16 chars of randomness (2^64 space) to prevent birthday attack collisions
	domain := fmt.Sprintf("req-%d-%s", time.Now().UnixNano(), randomID[:16])

	// Use domain as tracking key (both gateway and CRE know this)
	// CRE will generate its own event_id which we'll receive in the webhook
	trackingKey := domain

	// Create pending request with result channel
	pending := &PendingRequest{
		RequestID:  trackingKey,
		CreatedAt:  time.Now(),
		ResultChan: make(chan *WebhookPayload, 1),
		Status:     "pending",
	}

	// Check if we've hit the max pending requests limit
	s.requestsMutex.Lock()
	currentPending := len(s.pendingRequests)
	if currentPending >= s.config.MaxPending {
		s.requestsMutex.Unlock()
		s.logger.Warn("Max pending requests reached, rejecting CREATE request",
			zap.Int("current_pending", currentPending),
			zap.Int("max_pending", s.config.MaxPending),
		)
		http.Error(w, "Server at capacity, please retry later", http.StatusServiceUnavailable)
		return
	}
	s.pendingRequests[trackingKey] = pending
	currentPending = len(s.pendingRequests)
	s.requestsMutex.Unlock()

	// Update pending requests gauge
	pendingRequestsGauge.Set(float64(currentPending))

	s.logger.Info("CRE fallback initiated",
		zap.String("domain", domain),
		zap.Float64("threshold_price", th),
		zap.String("tracking_key", trackingKey),
		zap.Int("pending_count", currentPending),
		zap.Int("max_pending", s.config.MaxPending),
	)

	// Trigger CRE workflow with configured callback URL
	if err := s.triggerWorkflow("create", domain, &th, nil, s.config.CallbackURL); err != nil {
		s.logger.Error("Failed to trigger workflow",
			zap.String("domain", domain),
			zap.Error(err),
		)
		workflowTriggers.WithLabelValues("create", "error").Inc()

		// Clean up pending request on failure
		s.requestsMutex.Lock()
		delete(s.pendingRequests, trackingKey)
		currentPending = len(s.pendingRequests)
		s.requestsMutex.Unlock()
		pendingRequestsGauge.Set(float64(currentPending))

		// SECURITY: Don't expose internal error details to clients
		http.Error(w, "Failed to trigger workflow", http.StatusInternalServerError)
		return
	}
	workflowTriggers.WithLabelValues("create", "success").Inc()

	// Block waiting for webhook or timeout
	select {
	case result := <-pending.ResultChan:
		// Webhook arrived! Return result immediately
		tholdHash, tholdErr := getTholdHash(result)
		if tholdErr != nil {
			s.logger.Warn("Failed to extract thold_hash from webhook content",
				zap.String("domain", domain),
				zap.Error(tholdErr),
			)
		}
		s.logger.Info("CRE fallback completed",
			zap.String("domain", domain),
			zap.String("thold_hash", tholdHash),
			zap.String("event_id", truncateEventID(result.EventID)),
		)

		s.requestsMutex.Lock()
		pending.Status = "completed"
		pending.Result = result
		s.requestsMutex.Unlock()

		// Parse CRE response - already in core-ts PriceContract format
		var priceContract PriceContractResponse
		if err := json.Unmarshal([]byte(result.Content), &priceContract); err != nil {
			s.logger.Warn("Failed to parse webhook content JSON",
				zap.String("domain", domain),
				zap.Error(err),
			)
			// Fall back to raw content on parse error
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"raw": result.Content})
			return
		}

		// Calculate collateral ratio from the response
		collateralRatio := CalculateCollateralRatio(uint32(priceContract.BasePrice), uint32(priceContract.TholdPrice))

		// Cache the quote for future requests
		s.quoteCache.SetQuote(priceContract.CommitHash, &priceContract)

		response := QuoteResponse{
			PriceContractResponse: priceContract,
			CollateralRatio:       collateralRatio,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

	case <-time.After(s.config.BlockTimeout):
		// Timeout - return 202 with request_id for polling
		requestTimeouts.WithLabelValues("create").Inc()
		s.logger.Warn("CREATE request timeout",
			zap.String("domain", domain),
			zap.String("request_id", trackingKey),
			zap.Duration("timeout", s.config.BlockTimeout),
		)

		s.requestsMutex.Lock()
		pending.Status = "timeout"
		pending.TimedOut = true
		s.requestsMutex.Unlock()

		response := SyncResponse{
			Status:    "timeout",
			RequestID: trackingKey,
			Message:   "Request is still processing. Use GET /status/" + trackingKey + " to check status.",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted) // 202 Accepted
		json.NewEncoder(w).Encode(response)
	}
}

// handleCheck handles POST /check requests by triggering a CRE "check" workflow and blocking until the corresponding webhook arrives or s.config.BlockTimeout elapses.
// It validates the JSON body (domain and 40-char thold_hash), registers a PendingRequest keyed by domain (enforcing s.config.MaxPending), and invokes the workflow.
// If a matching webhook is received before timeout, the pending request is marked completed and the parsed PriceContractResponse is returned (falls back to raw content on JSON parse failure).
// If s.config.BlockTimeout elapses, the pending request is marked timed out and a 202 Accepted SyncResponse containing the request ID is returned for polling.
func (s *GatewayServer) handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// SECURITY: Limit request body size to 1MB to prevent memory exhaustion DoS attacks
	const maxBodySize = 1 << 20 // 1MB
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

	var req CheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate request - domain must be non-empty and not too long, thold_hash must be exactly 40 hex chars
	// Max domain length is 253 per DNS spec limit
	const maxDomainLength = 253
	if req.Domain == "" || len(req.Domain) > maxDomainLength || !isValidHex(req.TholdHash, 40) {
		http.Error(w, "Invalid domain or thold_hash", http.StatusBadRequest)
		return
	}

	// Use domain as tracking key
	trackingKey := req.Domain

	// Create pending request with result channel
	pending := &PendingRequest{
		RequestID:  trackingKey,
		CreatedAt:  time.Now(),
		ResultChan: make(chan *WebhookPayload, 1),
		Status:     "pending",
	}

	// Check if we've hit the max pending requests limit
	s.requestsMutex.Lock()
	currentPending := len(s.pendingRequests)
	if currentPending >= s.config.MaxPending {
		s.requestsMutex.Unlock()
		logger.Warn("Max pending requests reached, rejecting CHECK request",
			zap.Int("current_pending", currentPending),
			zap.Int("max_pending", s.config.MaxPending),
		)
		http.Error(w, "Server at capacity, please retry later", http.StatusServiceUnavailable)
		return
	}
	s.pendingRequests[trackingKey] = pending
	currentPending = len(s.pendingRequests)
	s.requestsMutex.Unlock()

	logger.Info("CHECK request initiated",
		zap.String("domain", req.Domain),
		zap.String("thold_hash", req.TholdHash),
		zap.String("tracking_key", trackingKey),
		zap.Int("pending_count", currentPending),
		zap.Int("max_pending", s.config.MaxPending),
	)

	// Trigger CRE workflow with configured callback URL
	if err := s.triggerWorkflow("check", req.Domain, nil, &req.TholdHash, s.config.CallbackURL); err != nil {
		logger.Error("Failed to trigger workflow",
			zap.String("domain", req.Domain),
			zap.Error(err),
		)
		workflowTriggers.WithLabelValues("check", "error").Inc()

		// Clean up pending request on failure
		s.requestsMutex.Lock()
		delete(s.pendingRequests, trackingKey)
		currentPending = len(s.pendingRequests)
		s.requestsMutex.Unlock()
		pendingRequestsGauge.Set(float64(currentPending))

		// SECURITY: Don't expose internal error details to clients
		http.Error(w, "Failed to trigger workflow", http.StatusInternalServerError)
		return
	}
	workflowTriggers.WithLabelValues("check", "success").Inc()

	// Block waiting for webhook or timeout
	select {
	case result := <-pending.ResultChan:
		// Webhook arrived! Return result immediately
		eventType := result.EventType
		if eventType == "breach" {
			logger.Info("BREACH detected - secret revealed",
				zap.String("domain", req.Domain),
			)
		} else {
			logger.Info("CHECK completed",
				zap.String("domain", req.Domain),
				zap.String("status", eventType),
			)
		}

		s.requestsMutex.Lock()
		pending.Status = "completed"
		pending.Result = result
		s.requestsMutex.Unlock()

		// Parse CRE response - already in core-ts PriceContract format
		var priceContract PriceContractResponse
		if err := json.Unmarshal([]byte(result.Content), &priceContract); err != nil {
			logger.Warn("Failed to parse content JSON",
				zap.String("domain", req.Domain),
				zap.Error(err),
			)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"raw": result.Content})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(priceContract)

	case <-time.After(s.config.BlockTimeout):
		// Timeout - return 202 with request_id for polling
		requestTimeouts.WithLabelValues("check").Inc()
		logger.Warn("CHECK request timeout",
			zap.String("domain", req.Domain),
			zap.String("request_id", trackingKey),
			zap.Duration("timeout", s.config.BlockTimeout),
		)

		s.requestsMutex.Lock()
		pending.Status = "timeout"
		pending.TimedOut = true
		s.requestsMutex.Unlock()

		response := SyncResponse{
			Status:    "timeout",
			RequestID: trackingKey,
			Message:   "Request is still processing. Use GET /status/" + trackingKey + " to check status.",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted) // 202 Accepted
		json.NewEncoder(w).Encode(response)
	}
}

// handleWebhook receives POST callbacks from the CRE workflow and unblocks waiting requests.
//
// Webhook Domain Resolution:
// The handler extracts the tracking domain from the webhook payload's tags. If no "domain" tag
// is present, it falls back to using the event_id as the domain key. This fallback ensures
// backward compatibility with CRE workflows that may not include explicit domain tags.
//
// Note for CRE Integration:
// CRE workflows should include a "domain" tag in their Nostr event to ensure proper request
// matching. The domain should match the request_id generated by handleCreate/handleCheck.
// Example: Tags: [["d", commit_hash], ["domain", request_id]]
func (s *GatewayServer) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// SECURITY: Limit request body size to 1MB to prevent memory exhaustion DoS attacks
	const maxBodySize = 1 << 20 // 1MB
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Error("Failed to read webhook body", zap.Error(err))
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var payload WebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		logger.Error("Failed to parse webhook JSON", zap.Error(err))
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// SECURITY: Validate Content field is not empty
	// Empty content would result in invalid/empty price contract data
	if payload.Content == "" {
		webhookSignatureFailures.WithLabelValues("empty_content").Inc()
		logger.Warn("Webhook has empty content field",
			zap.String("event_id", truncateEventID(payload.EventID)),
		)
		http.Error(w, "Webhook content cannot be empty", http.StatusBadRequest)
		return
	}

	// SECURITY: Validate Tags array is present
	// Tags are required for domain matching and Nostr event structure
	if payload.Tags == nil {
		webhookSignatureFailures.WithLabelValues("nil_tags").Inc()
		logger.Warn("Webhook has nil tags array",
			zap.String("event_id", truncateEventID(payload.EventID)),
		)
		http.Error(w, "Webhook tags cannot be nil", http.StatusBadRequest)
		return
	}

	// SECURITY: Check for replay attack BEFORE signature verification (fail fast)
	if s.isWebhookReplayed(payload.EventID) {
		webhookSignatureFailures.WithLabelValues("replay").Inc()
		logger.Warn("Duplicate webhook detected (replay attack prevention)",
			zap.String("event_id", truncateEventID(payload.EventID)),
		)
		http.Error(w, "Duplicate webhook", http.StatusConflict)
		return
	}

	// SECURITY: Verify webhook signature to prevent spoofed payloads
	// This ensures the webhook actually came from CRE with a valid Nostr event signature
	if err := verifyWebhookSignature(&payload); err != nil {
		webhookSignatureFailures.WithLabelValues("verification_failed").Inc()
		logger.Error("Webhook signature verification failed",
			zap.Error(err),
			zap.String("event_id", truncateEventID(payload.EventID)),
			zap.String("pubkey", payload.PubKey),
		)
		http.Error(w, "Signature verification failed", http.StatusUnauthorized)
		return
	}

	// SECURITY: Verify webhook is signed by expected CRE public key
	// This prevents attackers from forging valid signatures with their own keys
	// ExpectedWebhookPubKey is now MANDATORY (checked at startup)
	// Using constant-time comparison to prevent timing attacks
	if !secureCompare(payload.PubKey, s.config.ExpectedWebhookPubKey) {
		webhookSignatureFailures.WithLabelValues("wrong_pubkey").Inc()
		s.logger.Warn("Webhook signed by unauthorized key",
			zap.String("event_id", truncateEventID(payload.EventID)),
		)
		http.Error(w, "Webhook signed by unauthorized key", http.StatusUnauthorized)
		return
	}

	// SECURITY: Verify webhook timestamp freshness to prevent replay attacks
	// Webhooks older than 5 minutes are rejected to limit replay window
	// Allow 5 seconds of future drift to handle minor clock skew between servers
	const maxWebhookAge int64 = 5 * 60 // 5 minutes in seconds
	const maxClockSkew int64 = 5       // 5 seconds tolerance for future timestamps
	currentTime := time.Now().Unix()

	// SECURITY: Check for integer overflow by validating bounds directly
	// This prevents attacks using extreme timestamp values that could overflow
	if payload.CreatedAt > currentTime+maxClockSkew {
		// Future timestamp beyond acceptable clock skew - likely attack
		webhookSignatureFailures.WithLabelValues("future_timestamp").Inc()
		logger.Warn("Webhook has future timestamp beyond clock skew tolerance",
			zap.Int64("created_at", payload.CreatedAt),
			zap.Int64("current_time", currentTime),
			zap.String("event_id", truncateEventID(payload.EventID)),
		)
		http.Error(w, "Invalid timestamp", http.StatusUnauthorized)
		return
	}
	if payload.CreatedAt < currentTime-maxWebhookAge {
		webhookSignatureFailures.WithLabelValues("expired").Inc()
		logger.Warn("Webhook timestamp expired",
			zap.Int64("created_at", payload.CreatedAt),
			zap.Int64("current_time", currentTime),
			zap.Int64("max_age_seconds", maxWebhookAge),
			zap.String("event_id", truncateEventID(payload.EventID)),
		)
		http.Error(w, "Webhook expired", http.StatusUnauthorized)
		return
	}

	// Mark webhook as processed AFTER all validations pass
	s.markWebhookProcessed(payload.EventID)

	// Cache price data from webhook for the new quote flow
	// This allows handleCreate to serve quotes without calling CRE
	s.cacheWebhookPrice(&payload)

	// SECURITY: Extract domain from tags to match pending request
	// Domain tag is REQUIRED - no fallback to event_id to prevent spoofing
	domain := getTag(payload.Tags, "domain")
	if domain == "" {
		webhookSignatureFailures.WithLabelValues("missing_domain").Inc()
		s.logger.Warn("Webhook missing required domain tag",
			zap.String("event_id", truncateEventID(payload.EventID)),
		)
		http.Error(w, "Missing required domain tag", http.StatusBadRequest)
		return
	}

	// Find the pending request by domain
	// Copy channel reference while holding lock to prevent race with cleanup
	s.requestsMutex.Lock()
	pending, exists := s.pendingRequests[domain]
	var resultChan chan *WebhookPayload
	if exists && pending != nil {
		resultChan = pending.ResultChan
	}
	s.requestsMutex.Unlock()

	if !exists || resultChan == nil {
		// This is fine - might be a duplicate webhook from another DON node
		// or a request that already timed out
		webhooksReceived.WithLabelValues(payload.EventType, "no_match").Inc()
		logger.Debug("Webhook received but no pending request found",
			zap.String("domain", domain),
			zap.String("event_id", truncateEventID(payload.EventID)),
			zap.String("event_type", payload.EventType),
		)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return
	}

	// Send result to the channel (non-blocking)
	// Using local copy of channel and recover to handle race with cleanup
	// that may close the channel between our lock release and send
	func() {
		defer func() {
			if r := recover(); r != nil {
				// Channel was closed by cleanup goroutine - this is expected
				// in race conditions and is not an error
				webhooksReceived.WithLabelValues(payload.EventType, "channel_closed").Inc()
				logger.Debug("Channel closed during send (request cleaned up)",
					zap.String("domain", domain),
					zap.String("event_id", truncateEventID(payload.EventID)),
				)
			}
		}()
		select {
		case resultChan <- &payload:
			webhooksReceived.WithLabelValues(payload.EventType, "matched").Inc()
			logger.Info("Webhook received and matched",
				zap.String("event_type", payload.EventType),
				zap.String("domain", domain),
				zap.String("event_id", truncateEventID(payload.EventID)),
			)
		default:
			// Channel already has a result - this is a duplicate webhook
			webhooksReceived.WithLabelValues(payload.EventType, "duplicate").Inc()
			logger.Debug("Duplicate webhook ignored",
				zap.String("domain", domain),
				zap.String("event_id", truncateEventID(payload.EventID)),
			)
		}
	}()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// handleStatus responds to GET /status/{request_id} with the current state of a tracked request.
//
// If the request exists and its status is "completed" and the webhook payload can be unmarshaled
// into a PriceContractResponse, the handler returns that PriceContractResponse as JSON.
// Otherwise the handler returns a SyncResponse JSON envelope containing the request's status,
// request ID, and any captured Result; when status is "pending" the response includes a message
// indicating processing is still underway.
//
// The handler returns HTTP 405 for non-GET methods, 400 when request_id is missing, and 404 when
// the request_id is not found.
func (s *GatewayServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	requestID := strings.TrimPrefix(r.URL.Path, "/status/")
	if requestID == "" {
		http.Error(w, "Missing request_id", http.StatusBadRequest)
		return
	}

	s.requestsMutex.RLock()
	pending, exists := s.pendingRequests[requestID]
	s.requestsMutex.RUnlock()

	if !exists {
		http.Error(w, "Request not found", http.StatusNotFound)
		return
	}

	// If completed, return PriceContract directly (CRE already outputs correct format)
	if pending.Status == "completed" && pending.Result != nil {
		var priceContract PriceContractResponse
		if err := json.Unmarshal([]byte(pending.Result.Content), &priceContract); err == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(priceContract)
			return
		}
	}

	// For pending/timeout states, return standard response
	response := SyncResponse{
		Status:    pending.Status,
		RequestID: requestID,
		Result:    pending.Result,
	}

	if pending.Status == "pending" {
		response.Message = "Request is still processing"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Health check response
type HealthResponse struct {
	Status       string            `json:"status"`       // "healthy", "degraded", "unhealthy"
	Timestamp    string            `json:"timestamp"`    // ISO 8601 timestamp
	Version      string            `json:"version"`      // Application version
	Uptime       string            `json:"uptime"`       // How long the server has been running
	Dependencies map[string]Health `json:"dependencies"` // Status of dependencies
	Metrics      HealthMetrics     `json:"metrics"`      // Current metrics
}

type Health struct {
	Status      string  `json:"status"`            // "up", "down", "degraded"
	Latency     *string `json:"latency,omitempty"` // Response time if applicable
	Message     string  `json:"message,omitempty"` // Additional info
	LastChecked string  `json:"last_checked"`      // When this was last checked
}

type HealthMetrics struct {
	PendingRequests int     `json:"pending_requests"`
	MaxPending      int     `json:"max_pending"`
	CapacityUsed    float64 `json:"capacity_used_percent"`
}

var (
	serverStartTime = time.Now()
	appVersion      = "1.0.0" // Update this with actual version
)

// GET /health - Liveness probe (is the server running?)
func handleHealth(w http.ResponseWriter, r *http.Request) {
	// Health endpoints typically don't need CORS as they're for internal probes
	w.Header().Set("Content-Type", "application/json")

	// Simple liveness check - just verify server is responding
	response := map[string]string{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"uptime":    time.Since(serverStartTime).String(),
	}

	healthChecks.WithLabelValues("liveness", "healthy").Inc()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// GET /readiness - Readiness probe (is the server ready to accept traffic?)
func (s *GatewayServer) handleReadiness(w http.ResponseWriter, r *http.Request) {
	// Health endpoints typically don't need CORS as they're for internal probes
	w.Header().Set("Content-Type", "application/json")

	ctx := r.Context()

	// Check all dependencies
	deps := make(map[string]Health)
	overallStatus := "healthy"

	// 1. Check CRE Gateway reachability
	creHealth := s.checkCREGateway(ctx)
	deps["cre_gateway"] = creHealth
	if creHealth.Status != "up" {
		overallStatus = "degraded"
	}

	// 2. Check capacity
	s.requestsMutex.RLock()
	currentPending := len(s.pendingRequests)
	s.requestsMutex.RUnlock()

	capacityPercent := float64(currentPending) / float64(s.config.MaxPending) * 100
	capacityStatus := "up"
	capacityMessage := "Capacity available"

	if capacityPercent >= 90 {
		capacityStatus = "degraded"
		capacityMessage = "Near capacity limit"
		overallStatus = "degraded"
	} else if capacityPercent >= 100 {
		capacityStatus = "down"
		capacityMessage = "At capacity limit"
		overallStatus = "unhealthy"
	}

	deps["capacity"] = Health{
		Status:      capacityStatus,
		Message:     capacityMessage,
		LastChecked: time.Now().UTC().Format(time.RFC3339),
	}

	// 3. Check if private key is loaded
	if s.privateKey == nil {
		deps["authentication"] = Health{
			Status:      "down",
			Message:     "Private key not loaded",
			LastChecked: time.Now().UTC().Format(time.RFC3339),
		}
		overallStatus = "unhealthy"
	} else {
		deps["authentication"] = Health{
			Status:      "up",
			Message:     "Private key loaded",
			LastChecked: time.Now().UTC().Format(time.RFC3339),
		}
	}

	// Build response
	response := HealthResponse{
		Status:       overallStatus,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Version:      appVersion,
		Uptime:       time.Since(serverStartTime).String(),
		Dependencies: deps,
		Metrics: HealthMetrics{
			PendingRequests: currentPending,
			MaxPending:      s.config.MaxPending,
			CapacityUsed:    capacityPercent,
		},
	}

	// Set appropriate status code
	statusCode := http.StatusOK
	if overallStatus == "degraded" {
		statusCode = http.StatusOK // Still ready, but degraded
	} else if overallStatus == "unhealthy" {
		statusCode = http.StatusServiceUnavailable
	}

	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)

	// Record metrics
	healthChecks.WithLabelValues("readiness", overallStatus).Inc()

	// Update dependency status metrics
	for depName, depHealth := range deps {
		var statusValue float64
		switch depHealth.Status {
		case "up":
			statusValue = 1.0
		case "degraded":
			statusValue = 0.5
		case "down":
			statusValue = 0.0
		}
		dependencyStatus.WithLabelValues(depName).Set(statusValue)
	}

	// Log readiness check failures
	if overallStatus != "healthy" {
		logger.Warn("Readiness check failed",
			zap.String("status", overallStatus),
			zap.Any("dependencies", deps),
		)
	}
}

// checkCREGateway verifies connectivity to the CRE gateway
func (s *GatewayServer) checkCREGateway(ctx context.Context) Health {
	start := time.Now()

	// Create a HEAD request with timeout
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(checkCtx, "HEAD", s.config.GatewayURL, nil)
	if err != nil {
		return Health{
			Status:      "down",
			Message:     fmt.Sprintf("Failed to create request: %v", err),
			LastChecked: time.Now().UTC().Format(time.RFC3339),
		}
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Do(req)
	latency := time.Since(start)
	latencyStr := latency.String()

	if err != nil {
		logger.Warn("CRE gateway health check failed",
			zap.Error(err),
			zap.String("gateway_url", s.config.GatewayURL),
		)
		return Health{
			Status:      "down",
			Message:     fmt.Sprintf("Unreachable: %v", err),
			LastChecked: time.Now().UTC().Format(time.RFC3339),
		}
	}
	defer resp.Body.Close()

	// Consider any response (even 404) as "up" - we just care if it's reachable
	status := "up"
	message := "Reachable"

	if latency > 2*time.Second {
		status = "degraded"
		message = "Slow response time"
	}

	return Health{
		Status:      status,
		Latency:     &latencyStr,
		Message:     message,
		LastChecked: time.Now().UTC().Format(time.RFC3339),
	}
}

// triggerWorkflow sends HTTP trigger to CRE gateway using proper JWT format
// Uses circuit breaker to prevent cascading failures when CRE gateway is unavailable
func (s *GatewayServer) triggerWorkflow(op, domain string, tholdPrice *float64, tholdHash *string, callbackURL string) error {
	// Check circuit breaker before attempting request
	if !s.circuitBreaker.Allow() {
		s.logger.Warn("Circuit breaker open - rejecting request to CRE gateway",
			zap.String("operation", op),
			zap.String("domain", domain),
			zap.String("circuit_state", s.circuitBreaker.State()),
		)
		return fmt.Errorf("circuit breaker open: CRE gateway temporarily unavailable")
	}

	// Build input
	input := map[string]interface{}{
		"domain":       domain,
		"callback_url": callbackURL,
	}

	if tholdPrice != nil {
		input["thold_price"] = *tholdPrice
	}
	if tholdHash != nil {
		input["thold_hash"] = *tholdHash
	}

	// Create JSON-RPC request
	reqID := fmt.Sprintf("%d", time.Now().UnixNano())
	rpcRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      reqID,
		"method":  "workflows.execute",
		"params": map[string]interface{}{
			"input": input,
			"workflow": map[string]interface{}{
				"workflowID": s.config.WorkflowID,
			},
		},
	}

	// Use deterministic JSON marshaling for consistent digest computation
	// This ensures the same request always produces the same signature
	rpcJSON, err := marshalSorted(rpcRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal RPC request: %w", err)
	}

	// Compute SHA256 digest of the request
	digest := sha256.Sum256(rpcJSON)
	digestHex := "0x" + hex.EncodeToString(digest[:])

	// Generate cryptographically random request ID
	requestID, err := ethsign.GenerateRequestID()
	if err != nil {
		return fmt.Errorf("failed to generate request ID: %w", err)
	}

	// Generate JWT token using shared ethsign package
	token, err := ethsign.GenerateJWT(s.privateKey, s.config.AuthorizedKey, digestHex, requestID)
	if err != nil {
		return fmt.Errorf("failed to generate JWT: %w", err)
	}

	// Send request
	req, err := http.NewRequest("POST", s.config.GatewayURL, bytes.NewReader(rpcJSON))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		s.circuitBreaker.RecordFailure()
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 && resp.StatusCode != 202 {
		// 5xx errors indicate CRE gateway issues, trigger circuit breaker
		if resp.StatusCode >= 500 {
			s.circuitBreaker.RecordFailure()
		}
		return fmt.Errorf("non-success status %d: %s", resp.StatusCode, string(respBody))
	}

	// Success - record it to potentially close the circuit
	s.circuitBreaker.RecordSuccess()
	return nil
}

// truncateEventID safely truncates an event ID to 16 characters for logging.
// This prevents log injection attacks where attackers could embed malicious content
// in long event IDs. Returns the full string if shorter than 16 chars.
func truncateEventID(eventID string) string {
	if len(eventID) <= 16 {
		return eventID
	}
	return eventID[:16]
}

// getTag extracts the value for a given key from a Nostr-style tags slice.
// It returns the second element of the first tag whose first element equals key, or an empty string if no match is found.
func getTag(tags [][]string, key string) string {
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == key {
			return tag[1]
		}
	}
	return ""
}

// getTholdHash extracts the TholdHash field from the WebhookPayload's Content interpreted as a PriceContractResponse.
// Returns the thold_hash and any JSON parsing error encountered.
// Callers should handle the error case appropriately (e.g., log warning and use empty string).
func getTholdHash(payload *WebhookPayload) (string, error) {
	if payload == nil || payload.Content == "" {
		return "", fmt.Errorf("payload or content is nil/empty")
	}
	var priceContract PriceContractResponse
	if err := json.Unmarshal([]byte(payload.Content), &priceContract); err != nil {
		return "", fmt.Errorf("failed to parse content as PriceContractResponse: %w", err)
	}
	return priceContract.TholdHash, nil
}

// marshalSorted marshals v to JSON with all map keys sorted lexicographically at every level.
// This ensures deterministic output for consistent digest computation across requests.
func marshalSorted(v interface{}) ([]byte, error) {
	// Convert to map structure first via standard JSON round-trip
	temp, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	var data interface{}
	if err := json.Unmarshal(temp, &data); err != nil {
		return nil, err
	}

	// Custom marshal with sorted keys
	var buf bytes.Buffer
	if err := marshalSortedRecursive(&buf, data); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// marshalSortedRecursive writes the JSON encoding of v to buf with all map keys
// sorted lexicographically at every level.
func marshalSortedRecursive(buf *bytes.Buffer, v interface{}) error {
	switch val := v.(type) {
	case map[string]interface{}:
		buf.WriteString("{")
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for i, k := range keys {
			if i > 0 {
				buf.WriteString(",")
			}
			keyBytes, _ := json.Marshal(k)
			buf.Write(keyBytes)
			buf.WriteString(":")
			if err := marshalSortedRecursive(buf, val[k]); err != nil {
				return err
			}
		}
		buf.WriteString("}")
	case []interface{}:
		buf.WriteString("[")
		for i, item := range val {
			if i > 0 {
				buf.WriteString(",")
			}
			if err := marshalSortedRecursive(buf, item); err != nil {
				return err
			}
		}
		buf.WriteString("]")
	default:
		b, err := json.Marshal(val)
		if err != nil {
			return err
		}
		buf.Write(b)
	}
	return nil
}

// AtRiskVault represents a vault that is at risk of liquidation
type AtRiskVault struct {
	VaultID       string  `json:"vault_id"`
	TholdHash     string  `json:"thold_hash"`
	TholdPrice    float64 `json:"thold_price"`
	CurrentRatio  float64 `json:"current_ratio"`
	CollateralBTC float64 `json:"collateral_btc"`
	DebtDUSD      float64 `json:"debt_dusd"`
}

// AtRiskResponse is the response from the liquidation service
type AtRiskResponse struct {
	AtRiskVaults []AtRiskVault `json:"at_risk_vaults"`
	TotalCount   int           `json:"total_count"`
	CurrentPrice float64       `json:"current_price"`
	Threshold    float64       `json:"threshold"`
	Timestamp    int64         `json:"timestamp"`
}

// Prometheus metrics for liquidation polling
var (
	liquidationPollsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_liquidation_polls_total",
			Help: "Total number of liquidation service polls by status",
		},
		[]string{"status"},
	)

	liquidationAtRiskGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "gateway_liquidation_at_risk_count",
			Help: "Current number of at-risk vaults from last poll",
		},
	)

	liquidationPollDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "gateway_liquidation_poll_duration_seconds",
			Help:    "Liquidation poll latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	liquidationCheckTriggers = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_liquidation_check_triggers_total",
			Help: "Total number of CRE check triggers for at-risk vaults by status",
		},
		[]string{"status"},
	)
)

// pollLiquidationService periodically polls the liquidation service for at-risk vaults.
// It runs every config.LiquidationInterval (default 90 seconds) and logs at-risk vault info.
// This allows the gateway to be aware of vaults that may need liquidation and can trigger
// the CRE workflow to check their breach status.
func (s *GatewayServer) pollLiquidationService() {
	s.logger.Info("Starting liquidation service poller",
		zap.String("url", s.config.LiquidationURL),
		zap.Duration("interval", s.config.LiquidationInterval),
	)

	// Do an initial poll immediately
	s.doLiquidationPoll()

	ticker := time.NewTicker(s.config.LiquidationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.shutdownChan:
			s.logger.Info("Liquidation poller received shutdown signal")
			return
		case <-ticker.C:
			s.doLiquidationPoll()
		}
	}
}

// doLiquidationPoll makes a single request to the liquidation service and processes the response
func (s *GatewayServer) doLiquidationPoll() {
	start := time.Now()

	// Create HTTP request with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", s.config.LiquidationURL, nil)
	if err != nil {
		s.logger.Error("Failed to create liquidation poll request", zap.Error(err))
		liquidationPollsTotal.WithLabelValues("error").Inc()
		return
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		s.logger.Warn("Liquidation service unreachable",
			zap.Error(err),
			zap.String("url", s.config.LiquidationURL),
		)
		liquidationPollsTotal.WithLabelValues("unreachable").Inc()
		return
	}
	defer resp.Body.Close()

	duration := time.Since(start)
	liquidationPollDuration.Observe(duration.Seconds())

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		s.logger.Warn("Liquidation service returned non-200 status",
			zap.Int("status_code", resp.StatusCode),
			zap.String("body", string(body)),
		)
		liquidationPollsTotal.WithLabelValues("error").Inc()
		return
	}

	// Parse response
	var atRiskResp AtRiskResponse
	if err := json.NewDecoder(resp.Body).Decode(&atRiskResp); err != nil {
		s.logger.Error("Failed to parse liquidation service response", zap.Error(err))
		liquidationPollsTotal.WithLabelValues("parse_error").Inc()
		return
	}

	// Update metrics
	liquidationAtRiskGauge.Set(float64(atRiskResp.TotalCount))
	liquidationPollsTotal.WithLabelValues("success").Inc()

	// Log results
	if atRiskResp.TotalCount > 0 {
		s.logger.Info("At-risk vaults detected",
			zap.Int("count", atRiskResp.TotalCount),
			zap.Float64("current_price", atRiskResp.CurrentPrice),
			zap.Float64("threshold", atRiskResp.Threshold),
			zap.Duration("poll_duration", duration),
		)

		// Log details for each at-risk vault (up to first 10)
		logLimit := 10
		if len(atRiskResp.AtRiskVaults) < logLimit {
			logLimit = len(atRiskResp.AtRiskVaults)
		}
		for i := 0; i < logLimit; i++ {
			vault := atRiskResp.AtRiskVaults[i]
			s.logger.Debug("At-risk vault",
				zap.String("vault_id", vault.VaultID),
				zap.String("thold_hash", vault.TholdHash),
				zap.Float64("current_ratio", vault.CurrentRatio),
				zap.Float64("thold_price", vault.TholdPrice),
			)
		}
		if atRiskResp.TotalCount > logLimit {
			s.logger.Debug("Additional at-risk vaults not logged",
				zap.Int("remaining", atRiskResp.TotalCount-logLimit),
			)
		}

		// Trigger CRE check workflow for each at-risk vault to potentially reveal thold_key
		s.triggerCheckForAtRiskVaults(atRiskResp.AtRiskVaults)
	} else {
		s.logger.Debug("No at-risk vaults",
			zap.Float64("current_price", atRiskResp.CurrentPrice),
			zap.Float64("threshold", atRiskResp.Threshold),
			zap.Duration("poll_duration", duration),
		)
	}
}

// triggerBatchEvaluate triggers the CRE "evaluate" workflow with a batch of thold_hashes.
// This will cause the oracle to check if any prices have breached their thresholds and reveal
// the thold_key if so. The breach events are published to Nostr and picked up by the liquidation service.
func (s *GatewayServer) triggerCheckForAtRiskVaults(vaults []AtRiskVault) {
	if len(vaults) == 0 {
		return
	}

	// Collect all valid thold_hashes
	var tholdHashes []string
	for _, vault := range vaults {
		// Skip if thold_hash is empty or invalid (must be 40 hex chars)
		// Use isValidHex to prevent injection attacks via malformed data
		if !isValidHex(vault.TholdHash, 40) {
			s.logger.Debug("Skipping vault with invalid thold_hash",
				zap.String("vault_id", vault.VaultID),
				zap.String("thold_hash", vault.TholdHash),
			)
			continue
		}
		tholdHashes = append(tholdHashes, vault.TholdHash)
	}

	if len(tholdHashes) == 0 {
		s.logger.Debug("No valid thold_hashes to evaluate")
		return
	}

	s.logger.Info("Triggering batch CRE evaluate for at-risk vaults",
		zap.Int("count", len(tholdHashes)),
	)

	// Generate a unique domain for this batch evaluation
	domain := fmt.Sprintf("liq-batch-%d", time.Now().UnixNano())

	// Trigger the batch evaluate workflow
	err := s.triggerEvaluateWorkflow(domain, tholdHashes, s.config.CallbackURL)
	if err != nil {
		s.logger.Error("Failed to trigger batch evaluate workflow",
			zap.Int("batch_size", len(tholdHashes)),
			zap.Error(err),
		)
		liquidationCheckTriggers.WithLabelValues("error").Inc()
	} else {
		liquidationCheckTriggers.WithLabelValues("success").Inc()
		s.logger.Info("Triggered batch evaluate workflow",
			zap.Int("batch_size", len(tholdHashes)),
			zap.String("domain", domain),
		)
	}
}

// triggerEvaluateWorkflow sends HTTP trigger to CRE gateway for batch quote evaluation
func (s *GatewayServer) triggerEvaluateWorkflow(domain string, tholdHashes []string, callbackURL string) error {
	// Check circuit breaker before attempting request
	if !s.circuitBreaker.Allow() {
		s.logger.Warn("Circuit breaker open - rejecting evaluate request to CRE gateway",
			zap.String("domain", domain),
			zap.String("circuit_state", s.circuitBreaker.State()),
		)
		return fmt.Errorf("circuit breaker open: CRE gateway temporarily unavailable")
	}

	// Build input for evaluate workflow
	input := map[string]interface{}{
		"domain":       domain,
		"thold_hashes": tholdHashes,
		"callback_url": callbackURL,
	}

	// Create JSON-RPC request
	reqID := fmt.Sprintf("%d", time.Now().UnixNano())
	rpcRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      reqID,
		"method":  "workflows.execute",
		"params": map[string]interface{}{
			"input": input,
			"workflow": map[string]interface{}{
				"workflowID": s.config.WorkflowID,
			},
		},
	}

	// Use deterministic JSON marshaling for consistent digest computation
	rpcJSON, err := marshalSorted(rpcRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal RPC request: %w", err)
	}

	// Compute SHA256 digest of the request
	digest := sha256.Sum256(rpcJSON)
	digestHex := "0x" + hex.EncodeToString(digest[:])

	// Generate cryptographically random request ID
	requestID, err := ethsign.GenerateRequestID()
	if err != nil {
		return fmt.Errorf("failed to generate request ID: %w", err)
	}

	// Generate JWT token using shared ethsign package
	token, err := ethsign.GenerateJWT(s.privateKey, s.config.AuthorizedKey, digestHex, requestID)
	if err != nil {
		return fmt.Errorf("failed to generate JWT: %w", err)
	}

	// Send request
	req, err := http.NewRequest("POST", s.config.GatewayURL, bytes.NewReader(rpcJSON))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		s.circuitBreaker.RecordFailure()
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 && resp.StatusCode != 202 {
		// 5xx errors indicate CRE gateway issues, trigger circuit breaker
		if resp.StatusCode >= 500 {
			s.circuitBreaker.RecordFailure()
		}
		return fmt.Errorf("non-success status %d: %s", resp.StatusCode, string(respBody))
	}

	// Success - record it to potentially close the circuit
	s.circuitBreaker.RecordSuccess()
	return nil
}

// cleanupOldRequests periodically removes stale requests to prevent memory leaks.
// It respects the shutdownChan for graceful termination during server shutdown.
//
// Cleanup strategy:
//   - Remove completed requests older than 5 minutes
//   - Remove timed-out requests older than 5 minutes (clients should poll /status)
//   - Remove stale pending requests older than 2x s.config.BlockTimeout (edge case handling)
//
// SAFETY: We collect requests to delete first, then close their channels outside
// the main loop to prevent issues with concurrent channel operations.
func (s *GatewayServer) cleanupOldRequests() {
	ticker := time.NewTicker(s.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.shutdownChan:
			logger.Info("Cleanup goroutine received shutdown signal")
			return
		case <-ticker.C:
			// Collect requests to delete (don't modify map while iterating)
			var toDelete []string
			var channelsToClose []chan *WebhookPayload

			s.requestsMutex.Lock()
			now := time.Now()

			for id, req := range s.pendingRequests {
				shouldDelete := false

				if req.Status == "completed" && now.Sub(req.CreatedAt) > 5*time.Minute {
					shouldDelete = true
				} else if req.Status == "timeout" && now.Sub(req.CreatedAt) > 5*time.Minute {
					shouldDelete = true
				} else if req.Status == "pending" && now.Sub(req.CreatedAt) > 2*s.config.BlockTimeout {
					// Stale pending request that never completed or timed out (shouldn't happen)
					age := now.Sub(req.CreatedAt)
					logger.Warn("Cleaning up stale pending request",
						zap.String("request_id", id),
						zap.Duration("age", age),
						zap.String("status", req.Status),
					)
					shouldDelete = true
				}

				if shouldDelete {
					toDelete = append(toDelete, id)
					// Collect channel to close (only if not nil and request was pending)
					if req.ResultChan != nil && req.Status == "pending" {
						channelsToClose = append(channelsToClose, req.ResultChan)
					}
				}
			}

			// Delete collected requests
			for _, id := range toDelete {
				delete(s.pendingRequests, id)
			}

			currentPending := len(s.pendingRequests)
			s.requestsMutex.Unlock()

			// Close channels outside the lock to avoid blocking other operations
			// This signals any waiting handlers that the request was cleaned up
			for _, ch := range channelsToClose {
				close(ch)
			}

			cleaned := len(toDelete)

			if cleaned > 0 {
				requestsCleanedUp.Add(float64(cleaned))
				logger.Info("Cleanup completed",
					zap.Int("removed", cleaned),
					zap.Int("pending", currentPending),
					zap.Int("max_pending", s.config.MaxPending),
				)
			}

			// Update gauge after cleanup
			pendingRequestsGauge.Set(float64(currentPending))

			// Clean up stale IP rate limiters (IPs not seen in 10 minutes)
			ipsCleaned := s.ipRateLimiter.Cleanup(10 * time.Minute)
			if ipsCleaned > 0 {
				logger.Debug("Cleaned up stale IP rate limiters", zap.Int("count", ipsCleaned))
			}

			// Clean up webhook replay protection cache
			webhooksCleaned := s.cleanupWebhookCache()
			if webhooksCleaned > 0 {
				logger.Debug("Cleaned up expired webhook entries", zap.Int("count", webhooksCleaned))
			}
		}
	}
}
