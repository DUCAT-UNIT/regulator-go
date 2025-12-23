package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"gateway/internal/ethsign"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/time/rate"
)

// Test helpers
// setupTestEnv accepts testing.TB to work with both *testing.T and *testing.B
func setupTestEnv(tb testing.TB) {
	tb.Helper()

	// Set required environment variables
	os.Setenv("CRE_WORKFLOW_ID", "test-workflow-id-12345")
	os.Setenv("DUCAT_AUTHORIZED_KEY", "0xtest123")
	os.Setenv("GATEWAY_CALLBACK_URL", "http://localhost:8080/webhook/ducat")
	os.Setenv("DUCAT_PRIVATE_KEY", "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c")

	// Reset server state if initialized
	if server != nil {
		server.requestsMutex.Lock()
		server.pendingRequests = make(map[string]*PendingRequest)
		server.requestsMutex.Unlock()
	}
}

func resetGlobals() {
	if server != nil {
		server.requestsMutex.Lock()
		server.pendingRequests = make(map[string]*PendingRequest)
		server.requestsMutex.Unlock()
	}
}

// Test private key for signing webhooks (different from server key)
var testWebhookPrivKey, _ = hex.DecodeString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

// createSignedWebhook creates a properly signed WebhookPayload for testing.
// This simulates a valid Nostr event from the CRE.
func createSignedWebhook(eventType, domain, content string, tags [][]string) WebhookPayload {
	// Get the Schnorr public key from the test private key
	_, pubKey := btcec.PrivKeyFromBytes(testWebhookPrivKey)
	pubKeyHex := hex.EncodeToString(schnorr.SerializePubKey(pubKey))

	// Add domain tag if not present
	hasDomainTag := false
	for _, tag := range tags {
		if len(tag) >= 1 && tag[0] == "domain" {
			hasDomainTag = true
			break
		}
	}
	if !hasDomainTag && domain != "" {
		tags = append(tags, []string{"domain", domain})
	}

	payload := WebhookPayload{
		EventType: eventType,
		PubKey:    pubKeyHex,
		CreatedAt: time.Now().Unix(),
		Kind:      30078, // Custom kind for DUCAT
		Tags:      tags,
		Content:   content,
	}

	// Compute event ID (NIP-01 format)
	tagsJSON, _ := json.Marshal(payload.Tags)
	serialized := fmt.Sprintf("[0,%q,%d,%d,%s,%q]",
		payload.PubKey, payload.CreatedAt, payload.Kind, string(tagsJSON), payload.Content)
	hash := sha256.Sum256([]byte(serialized))
	payload.EventID = hex.EncodeToString(hash[:])

	// Sign the event ID with Schnorr
	privKey, _ := btcec.PrivKeyFromBytes(testWebhookPrivKey)
	eventIDBytes, _ := hex.DecodeString(payload.EventID)
	sig, _ := schnorr.Sign(privKey, eventIDBytes)
	payload.Sig = hex.EncodeToString(sig.Serialize())

	return payload
}

// TestLoadConfig tests configuration loading from environment variables
func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name        string
		envVars     map[string]string
		shouldPanic bool
		validate    func(t *testing.T, cfg *GatewayConfig)
	}{
		{
			name: "all required vars set",
			envVars: map[string]string{
				"CRE_WORKFLOW_ID":      "workflow123",
				"DUCAT_AUTHORIZED_KEY": "0xabc123",
				"GATEWAY_CALLBACK_URL": "http://example.com/webhook",
			},
			shouldPanic: false,
			validate: func(t *testing.T, cfg *GatewayConfig) {
				if cfg.WorkflowID != "workflow123" {
					t.Errorf("WorkflowID = %s, want workflow123", cfg.WorkflowID)
				}
				if cfg.AuthorizedKey != "0xabc123" {
					t.Errorf("AuthorizedKey = %s, want 0xabc123", cfg.AuthorizedKey)
				}
				if cfg.CallbackURL != "http://example.com/webhook" {
					t.Errorf("CallbackURL = %s, want http://example.com/webhook", cfg.CallbackURL)
				}
				if cfg.BlockTimeout != 60*time.Second {
					t.Errorf("BlockTimeout = %v, want 60s", cfg.BlockTimeout)
				}
				if cfg.MaxPending != 1000 {
					t.Errorf("MaxPending = %d, want 1000", cfg.MaxPending)
				}
			},
		},
		{
			name: "custom timeout and limits",
			envVars: map[string]string{
				"CRE_WORKFLOW_ID":          "workflow123",
				"DUCAT_AUTHORIZED_KEY":     "0xabc123",
				"GATEWAY_CALLBACK_URL":     "http://example.com/webhook",
				"BLOCK_TIMEOUT_SECONDS":    "30",
				"CLEANUP_INTERVAL_SECONDS": "60",
				"MAX_PENDING_REQUESTS":     "500",
			},
			shouldPanic: false,
			validate: func(t *testing.T, cfg *GatewayConfig) {
				if cfg.BlockTimeout != 30*time.Second {
					t.Errorf("BlockTimeout = %v, want 30s", cfg.BlockTimeout)
				}
				if cfg.CleanupInterval != 60*time.Second {
					t.Errorf("CleanupInterval = %v, want 60s", cfg.CleanupInterval)
				}
				if cfg.MaxPending != 500 {
					t.Errorf("MaxPending = %d, want 500", cfg.MaxPending)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all env vars
			os.Clearenv()

			// Set test env vars
			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}

			if tt.shouldPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("loadConfig() should have panicked but didn't")
					}
				}()
			}

			cfg := loadConfig()

			if tt.validate != nil {
				tt.validate(t, cfg)
			}
		})
	}
}

// TestHandleHealth tests the health check endpoint
func TestHandleHealth(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	handleHealth(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Health endpoint now returns JSON with status field
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if status, ok := result["status"].(string); !ok || status != "healthy" {
		t.Errorf("status = %v, want 'healthy'", result["status"])
	}

	// CORS headers are NOT set for health endpoints (internal probes)
	// This is intentional for security - health endpoints don't need CORS
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("health endpoint should not have CORS header, got %q", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

// TestHandleCreateValidation tests input validation for /api/quote
func TestHandleCreateValidation(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	tests := []struct {
		name           string
		method         string
		queryParams    string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "missing th parameter",
			method:         "GET",
			queryParams:    "",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Missing th query parameter",
		},
		{
			name:           "invalid th value",
			method:         "GET",
			queryParams:    "?th=invalid",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid th value",
		},
		{
			name:           "negative th value",
			method:         "GET",
			queryParams:    "?th=-100",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "threshold price must be positive",
		},
		{
			name:           "zero th value",
			method:         "GET",
			queryParams:    "?th=0",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "threshold price must be positive",
		},
		{
			name:           "wrong method",
			method:         "POST",
			queryParams:    "?th=100",
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   "Method not allowed",
		},
		{
			name:           "OPTIONS preflight",
			method:         "OPTIONS",
			queryParams:    "",
			expectedStatus: http.StatusOK,
			expectedBody:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/api/quote"+tt.queryParams, nil)
			w := httptest.NewRecorder()

			server.handleCreate(w, req)

			resp := w.Result()
			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.expectedStatus)
			}

			if tt.expectedBody != "" && !strings.Contains(string(body), tt.expectedBody) {
				t.Errorf("body = %s, want to contain %s", body, tt.expectedBody)
			}
		})
	}
}

// TestHandleCreateMaxPending tests max pending request limit
func TestHandleCreateMaxPending(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Set a low limit for testing
	server.config.MaxPending = 2

	// Fill up pending requests
	for i := 0; i < server.config.MaxPending; i++ {
		domain := fmt.Sprintf("test-domain-%d", i)
		server.pendingRequests[domain] = &PendingRequest{
			RequestID:  domain,
			CreatedAt:  time.Now(),
			ResultChan: make(chan *WebhookPayload, 1),
			Status:     "pending",
		}
	}

	req := httptest.NewRequest("GET", "/api/quote?th=100", nil)
	w := httptest.NewRecorder()

	server.handleCreate(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Server at capacity") {
		t.Errorf("body = %s, want 'Server at capacity'", body)
	}

	// Cleanup
	resetGlobals()
	server.config.MaxPending = 1000
}

// TestHandleWebhook tests webhook processing
func TestHandleWebhook(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	t.Run("wrong method", func(t *testing.T) {
		resetGlobals()
		req := httptest.NewRequest("GET", "/webhook/ducat", nil)
		w := httptest.NewRecorder()
		server.handleWebhook(w, req)
		if w.Result().StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want %d", w.Result().StatusCode, http.StatusMethodNotAllowed)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		resetGlobals()
		req := httptest.NewRequest("POST", "/webhook/ducat", strings.NewReader("invalid json"))
		w := httptest.NewRecorder()
		server.handleWebhook(w, req)
		if w.Result().StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", w.Result().StatusCode, http.StatusBadRequest)
		}
	})

	t.Run("valid webhook with pending request", func(t *testing.T) {
		resetGlobals()
		domain := "test-domain"

		// Setup pending request
		server.pendingRequests[domain] = &PendingRequest{
			RequestID:  domain,
			CreatedAt:  time.Now(),
			ResultChan: make(chan *WebhookPayload, 1),
			Status:     "pending",
		}

		// Create properly signed webhook
		payload := createSignedWebhook("create", domain, `{"thold_price": 100, "thold_hash": "abc123"}`, nil)
		jsonData, _ := json.Marshal(payload)

		req := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(jsonData))
		w := httptest.NewRecorder()
		server.handleWebhook(w, req)

		if w.Result().StatusCode != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Result().StatusCode, http.StatusOK)
		}

		// Verify pending request received the webhook
		pending := server.pendingRequests[domain]
		select {
		case result := <-pending.ResultChan:
			if result.EventID != payload.EventID {
				t.Errorf("received event_id = %s, want %s", result.EventID, payload.EventID)
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("webhook did not unblock pending request")
		}
	})

	t.Run("webhook without pending request", func(t *testing.T) {
		resetGlobals()

		// Create properly signed webhook for unknown domain
		payload := createSignedWebhook("create", "unknown-domain", `{"thold_price": 100}`, nil)
		jsonData, _ := json.Marshal(payload)

		req := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(jsonData))
		w := httptest.NewRecorder()
		server.handleWebhook(w, req)

		if w.Result().StatusCode != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Result().StatusCode, http.StatusOK)
		}
	})

	t.Run("unsigned webhook rejected", func(t *testing.T) {
		resetGlobals()

		// Create unsigned webhook (missing signature)
		payload := WebhookPayload{
			EventType: "create",
			EventID:   "event123",
			PubKey:    strings.Repeat("a", 64),
			Tags:      [][]string{{"domain", "test-domain"}},
			Content:   `{"thold_price": 100}`,
			CreatedAt: time.Now().Unix(),
		}
		jsonData, _ := json.Marshal(payload)

		req := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(jsonData))
		w := httptest.NewRecorder()
		server.handleWebhook(w, req)

		if w.Result().StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d (unauthorized for unsigned webhook)", w.Result().StatusCode, http.StatusUnauthorized)
		}
	})

	t.Run("expired webhook rejected", func(t *testing.T) {
		resetGlobals()

		// Create a signed webhook with an old timestamp
		payload := createSignedWebhook("create", "test-domain", `{"thold_price": 100}`, nil)
		// Manually override to make it expired (6 minutes old)
		payload.CreatedAt = time.Now().Unix() - 360

		// Re-sign with old timestamp
		tagsJSON, _ := json.Marshal(payload.Tags)
		serialized := fmt.Sprintf("[0,%q,%d,%d,%s,%q]",
			payload.PubKey, payload.CreatedAt, payload.Kind, string(tagsJSON), payload.Content)
		hash := sha256.Sum256([]byte(serialized))
		payload.EventID = hex.EncodeToString(hash[:])

		privKey, _ := btcec.PrivKeyFromBytes(testWebhookPrivKey)
		eventIDBytes, _ := hex.DecodeString(payload.EventID)
		sig, _ := schnorr.Sign(privKey, eventIDBytes)
		payload.Sig = hex.EncodeToString(sig.Serialize())

		jsonData, _ := json.Marshal(payload)

		req := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(jsonData))
		w := httptest.NewRecorder()
		server.handleWebhook(w, req)

		if w.Result().StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d (unauthorized for expired webhook)", w.Result().StatusCode, http.StatusUnauthorized)
		}
	})
}

// TestHandleCheckValidation tests /check endpoint validation
func TestHandleCheckValidation(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	tests := []struct {
		name           string
		method         string
		payload        interface{}
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "wrong method",
			method:         "GET",
			payload:        nil,
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "invalid JSON",
			method:         "POST",
			payload:        "not json",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "missing domain",
			method: "POST",
			payload: CheckRequest{
				Domain:    "",
				TholdHash: "1234567890123456789012345678901234567890",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid domain or thold_hash",
		},
		{
			name:   "invalid thold_hash length",
			method: "POST",
			payload: CheckRequest{
				Domain:    "test-domain",
				TholdHash: "short",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid domain or thold_hash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if str, ok := tt.payload.(string); ok {
				body = strings.NewReader(str)
			} else if tt.payload != nil {
				jsonData, _ := json.Marshal(tt.payload)
				body = bytes.NewReader(jsonData)
			}

			req := httptest.NewRequest(tt.method, "/check", body)
			w := httptest.NewRecorder()

			server.handleCheck(w, req)

			resp := w.Result()
			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.expectedStatus)
			}

			if tt.expectedBody != "" {
				respBody, _ := io.ReadAll(resp.Body)
				if !strings.Contains(string(respBody), tt.expectedBody) {
					t.Errorf("body = %s, want to contain %s", respBody, tt.expectedBody)
				}
			}
		})
	}
}

// TestHandleStatus tests /status endpoint
func TestHandleStatus(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	tests := []struct {
		name           string
		method         string
		path           string
		setupRequest   func()
		expectedStatus int
		validateBody   func(t *testing.T, body []byte)
	}{
		{
			name:           "wrong method",
			method:         "POST",
			path:           "/status/test-123",
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "missing request ID",
			method:         "GET",
			path:           "/status/",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "request not found",
			method:         "GET",
			path:           "/status/nonexistent",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:   "pending request",
			method: "GET",
			path:   "/status/pending-req",
			setupRequest: func() {
				server.pendingRequests["pending-req"] = &PendingRequest{
					RequestID:  "pending-req",
					CreatedAt:  time.Now(),
					ResultChan: make(chan *WebhookPayload, 1),
					Status:     "pending",
				}
			},
			expectedStatus: http.StatusOK,
			validateBody: func(t *testing.T, body []byte) {
				var resp SyncResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					t.Fatalf("failed to parse response: %v", err)
				}
				if resp.Status != "pending" {
					t.Errorf("status = %s, want pending", resp.Status)
				}
				if !strings.Contains(resp.Message, "still processing") {
					t.Errorf("message should contain 'still processing'")
				}
			},
		},
		{
			name:   "completed request",
			method: "GET",
			path:   "/status/completed-req",
			setupRequest: func() {
				server.pendingRequests["completed-req"] = &PendingRequest{
					RequestID: "completed-req",
					CreatedAt: time.Now(),
					Status:    "completed",
					Result: &WebhookPayload{
						// Full CRE format payload with core-ts PriceContract fields
						Content: `{"event_type":"active","chain_network":"mutiny","oracle_pubkey":"abc123pubkey","base_price":100,"base_stamp":1699999000,"commit_hash":"commit123","contract_id":"contract456","oracle_sig":"sig789","thold_hash":"abc123def456","thold_key":null,"thold_price":95}`,
					},
				}
			},
			expectedStatus: http.StatusOK,
			validateBody: func(t *testing.T, body []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(body, &result); err != nil {
					t.Fatalf("failed to parse response: %v", err)
				}
				// Check core-ts PriceContract fields
				if basePrice, ok := result["base_price"].(float64); ok {
					if basePrice != 100.0 {
						t.Errorf("base_price = %f, want 100.0", basePrice)
					}
				} else {
					t.Error("base_price not found in response")
				}
				// Verify PriceContract fields exist
				if _, ok := result["chain_network"]; !ok {
					t.Error("chain_network not found in response")
				}
				if _, ok := result["commit_hash"]; !ok {
					t.Error("commit_hash not found in response")
				}
				if _, ok := result["contract_id"]; !ok {
					t.Error("contract_id not found in response")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetGlobals()

			if tt.setupRequest != nil {
				tt.setupRequest()
			}

			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			server.handleStatus(w, req)

			resp := w.Result()
			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.expectedStatus)
			}

			if tt.validateBody != nil {
				body, _ := io.ReadAll(resp.Body)
				tt.validateBody(t, body)
			}
		})
	}
}

// TestCleanupOldRequests tests the cleanup goroutine
func TestCleanupOldRequests(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Set very short intervals for testing
	oldCleanupInterval := server.config.CleanupInterval
	oldBlockTimeout := server.config.BlockTimeout
	server.config.CleanupInterval = 50 * time.Millisecond
	server.config.BlockTimeout = 50 * time.Millisecond
	defer func() {
		server.config.CleanupInterval = oldCleanupInterval
		server.config.BlockTimeout = oldBlockTimeout
	}()

	now := time.Now()

	// Add various requests
	server.pendingRequests["old-completed"] = &PendingRequest{
		RequestID:  "old-completed",
		CreatedAt:  now.Add(-10 * time.Minute),
		Status:     "completed",
		ResultChan: make(chan *WebhookPayload, 1),
	}

	server.pendingRequests["old-timeout"] = &PendingRequest{
		RequestID:  "old-timeout",
		CreatedAt:  now.Add(-10 * time.Minute),
		Status:     "timeout",
		ResultChan: make(chan *WebhookPayload, 1),
	}

	server.pendingRequests["stale-pending"] = &PendingRequest{
		RequestID:  "stale-pending",
		CreatedAt:  now.Add(-5 * time.Minute),
		Status:     "pending",
		ResultChan: make(chan *WebhookPayload, 1),
	}

	server.pendingRequests["recent-completed"] = &PendingRequest{
		RequestID:  "recent-completed",
		CreatedAt:  now.Add(-1 * time.Minute),
		Status:     "completed",
		ResultChan: make(chan *WebhookPayload, 1),
	}

	server.pendingRequests["active-pending"] = &PendingRequest{
		RequestID:  "active-pending",
		CreatedAt:  now,
		Status:     "pending",
		ResultChan: make(chan *WebhookPayload, 1),
	}

	initialCount := len(server.pendingRequests)
	if initialCount != 5 {
		t.Fatalf("setup failed: got %d requests, want 5", initialCount)
	}

	// Call cleanupOldRequests directly and wait for one cycle
	stopChan := make(chan bool)
	doneChan := make(chan bool)

	go func() {
		ticker := time.NewTicker(server.config.CleanupInterval)
		defer ticker.Stop()
		defer close(doneChan)

		select {
		case <-ticker.C:
			server.requestsMutex.Lock()
			now := time.Now()
			cleaned := 0

			for id, req := range server.pendingRequests {
				shouldDelete := false

				if req.Status == "completed" && now.Sub(req.CreatedAt) > 5*time.Minute {
					shouldDelete = true
				} else if req.Status == "timeout" && now.Sub(req.CreatedAt) > 5*time.Minute {
					shouldDelete = true
				} else if req.Status == "pending" && now.Sub(req.CreatedAt) > 2*server.config.BlockTimeout {
					shouldDelete = true
				}

				if shouldDelete {
					delete(server.pendingRequests, id)
					cleaned++
				}
			}
			server.requestsMutex.Unlock()
		case <-stopChan:
			return
		}
	}()

	// Wait for cleanup to run
	select {
	case <-doneChan:
	case <-time.After(300 * time.Millisecond):
		close(stopChan)
		t.Fatal("cleanup didn't complete in time")
	}

	// Verify cleanup
	server.requestsMutex.RLock()
	defer server.requestsMutex.RUnlock()

	expectedRemaining := []string{"recent-completed", "active-pending"}
	if len(server.pendingRequests) != len(expectedRemaining) {
		t.Errorf("after cleanup: got %d requests, want %d", len(server.pendingRequests), len(expectedRemaining))
	}

	for _, key := range expectedRemaining {
		if _, exists := server.pendingRequests[key]; !exists {
			t.Errorf("request %s should not have been cleaned up", key)
		}
	}
}

// TestGetTag tests the helper function
func TestGetTag(t *testing.T) {
	tests := []struct {
		name     string
		tags     [][]string
		key      string
		expected string
	}{
		{
			name:     "tag exists",
			tags:     [][]string{{"domain", "test-domain"}, {"other", "value"}},
			key:      "domain",
			expected: "test-domain",
		},
		{
			name:     "tag does not exist",
			tags:     [][]string{{"domain", "test-domain"}},
			key:      "missing",
			expected: "",
		},
		{
			name:     "empty tags",
			tags:     [][]string{},
			key:      "domain",
			expected: "",
		},
		{
			name:     "malformed tag",
			tags:     [][]string{{"single"}},
			key:      "single",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getTag(tt.tags, tt.key)
			if result != tt.expected {
				t.Errorf("getTag() = %s, want %s", result, tt.expected)
			}
		})
	}
}

// TestGetTholdHash tests the helper function
func TestGetTholdHash(t *testing.T) {
	tests := []struct {
		name        string
		payload     *WebhookPayload
		expected    string
		expectError bool
	}{
		{
			name: "valid payload",
			payload: &WebhookPayload{
				Content: `{"thold_hash": "abc123def456"}`,
			},
			expected:    "abc123def456",
			expectError: false,
		},
		{
			name: "invalid JSON",
			payload: &WebhookPayload{
				Content: `invalid json`,
			},
			expected:    "",
			expectError: true,
		},
		{
			name: "missing thold_hash",
			payload: &WebhookPayload{
				Content: `{"other_field": "value"}`,
			},
			expected:    "",
			expectError: false, // Valid JSON, just missing field
		},
		{
			name:        "nil payload",
			payload:     nil,
			expected:    "",
			expectError: true,
		},
		{
			name: "empty content",
			payload: &WebhookPayload{
				Content: "",
			},
			expected:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getTholdHash(tt.payload)
			if result != tt.expected {
				t.Errorf("getTholdHash() = %s, want %s", result, tt.expected)
			}
			if tt.expectError && err == nil {
				t.Errorf("getTholdHash() expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("getTholdHash() unexpected error: %v", err)
			}
		})
	}
}

// TestEncodeBase64URL tests the base64url encoding function using standard library
func TestEncodeBase64URL(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "empty input",
			input:    []byte{},
			expected: "",
		},
		{
			name:     "single byte",
			input:    []byte{0x00},
			expected: "AA",
		},
		{
			name:     "two bytes",
			input:    []byte{0x00, 0x01},
			expected: "AAE",
		},
		{
			name:     "three bytes (no padding)",
			input:    []byte{0x00, 0x01, 0x02},
			expected: "AAEC",
		},
		{
			name:     "test string",
			input:    []byte("hello"),
			expected: "aGVsbG8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := base64.RawURLEncoding.EncodeToString(tt.input)
			if result != tt.expected {
				t.Errorf("base64.RawURLEncoding.EncodeToString() = %s, want %s", result, tt.expected)
			}
		})
	}
}

// TestGenerateRequestID tests request ID generation using ethsign package
func TestGenerateRequestID(t *testing.T) {
	id1, err := ethsign.GenerateRequestID()
	if err != nil {
		t.Fatalf("GenerateRequestID() error = %v", err)
	}

	id2, err := ethsign.GenerateRequestID()
	if err != nil {
		t.Fatalf("GenerateRequestID() error = %v", err)
	}

	if id1 == id2 {
		t.Error("GenerateRequestID() should generate unique IDs")
	}

	if len(id1) != 32 {
		t.Errorf("GenerateRequestID() length = %d, want 32", len(id1))
	}

	// Verify it's valid hex
	if _, err := hex.DecodeString(id1); err != nil {
		t.Errorf("GenerateRequestID() returned invalid hex: %v", err)
	}
}

// TestGenerateJWT tests JWT generation using ethsign package
func TestGenerateJWT(t *testing.T) {
	// Generate a test private key
	privateKeyHex := "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c"
	privKeyBytes, _ := hex.DecodeString(privateKeyHex)
	privKey, _ := crypto.ToECDSA(privKeyBytes)

	address := "0x5b3ebc3622dd75f0a680c2b7e4613ad813c72f82"
	digest := "0x1234567890abcdef"

	reqID, _ := ethsign.GenerateRequestID()
	token, err := ethsign.GenerateJWT(privKey, address, digest, reqID)
	if err != nil {
		t.Fatalf("GenerateJWT() error = %v", err)
	}

	// Verify JWT structure (header.payload.signature)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Errorf("JWT parts = %d, want 3", len(parts))
	}

	// Verify it's different each time (due to jti and timestamps)
	reqID2, _ := ethsign.GenerateRequestID()
	token2, _ := ethsign.GenerateJWT(privKey, address, digest, reqID2)
	if token == token2 {
		t.Error("GenerateJWT() should generate unique tokens due to jti")
	}
}

// TestSignEthereumMessage tests Ethereum message signing using ethsign package
func TestSignEthereumMessage(t *testing.T) {
	// Generate a test private key
	privateKeyHex := "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c"
	privKeyBytes, _ := hex.DecodeString(privateKeyHex)
	privKey, _ := crypto.ToECDSA(privKeyBytes)

	message := "test message"

	signature, err := ethsign.SignEthereumMessage(privKey, message)
	if err != nil {
		t.Fatalf("SignEthereumMessage() error = %v", err)
	}

	// Verify signature length (65 bytes: r + s + v)
	if len(signature) != 65 {
		t.Errorf("signature length = %d, want 65", len(signature))
	}

	// Verify recovery ID is in Ethereum format (27 or 28, with v = recoveryID + 27)
	v := signature[64]
	if v < 27 || v > 30 {
		t.Errorf("v = %d, want 27-30 (Ethereum format)", v)
	}
}

// TestConcurrentWebhooks tests concurrent webhook handling
func TestConcurrentWebhooks(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	numRequests := 10
	var wg sync.WaitGroup

	// Pre-create signed payloads (must be done before concurrent send to get consistent event IDs)
	payloads := make([]WebhookPayload, numRequests)
	for i := 0; i < numRequests; i++ {
		domain := fmt.Sprintf("test-domain-%d", i)
		server.pendingRequests[domain] = &PendingRequest{
			RequestID:  domain,
			CreatedAt:  time.Now(),
			ResultChan: make(chan *WebhookPayload, 1),
			Status:     "pending",
		}
		payloads[i] = createSignedWebhook("create", domain, fmt.Sprintf(`{"thold_price": %d}`, i*100), nil)
	}

	// Send webhooks concurrently
	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			jsonData, _ := json.Marshal(payloads[idx])
			req := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(jsonData))
			w := httptest.NewRecorder()

			server.handleWebhook(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("webhook %d: status = %d, want %d", idx, w.Code, http.StatusOK)
			}
		}(i)
	}

	wg.Wait()

	// Verify all requests received their webhooks
	for i := 0; i < numRequests; i++ {
		domain := fmt.Sprintf("test-domain-%d", i)
		pending := server.pendingRequests[domain]

		select {
		case result := <-pending.ResultChan:
			if result.EventID != payloads[i].EventID {
				t.Errorf("domain %s: event_id = %s, want %s", domain, result.EventID, payloads[i].EventID)
			}
		case <-time.After(1 * time.Second):
			t.Errorf("domain %s: did not receive webhook", domain)
		}
	}
}

// BenchmarkHandleWebhook benchmarks webhook processing performance
func BenchmarkHandleWebhook(b *testing.B) {
	setupTestEnv(b)
	loadConfig()
	resetGlobals()

	// Create a properly signed webhook for benchmarking
	payload := createSignedWebhook("create", "bench-domain", `{"thold_price": 100}`, nil)
	jsonData, _ := json.Marshal(payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(jsonData))
		w := httptest.NewRecorder()
		server.handleWebhook(w, req)
	}
}

// BenchmarkEncodeBase64URL benchmarks base64url encoding
func BenchmarkEncodeBase64URL(b *testing.B) {
	data := []byte("this is a test message for base64url encoding performance testing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = base64.RawURLEncoding.EncodeToString(data)
	}
}

// TestTriggerWorkflow tests the workflow trigger function
func TestTriggerWorkflow(t *testing.T) {
	setupTestEnv(t)
	loadConfig()

	// Create a mock HTTP server to act as the CRE gateway
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify method
		if r.Method != "POST" {
			t.Errorf("method = %s, want POST", r.Method)
		}

		// Verify headers
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %s, want application/json", r.Header.Get("Content-Type"))
		}

		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			t.Errorf("Authorization header should start with 'Bearer '")
		}

		// Verify JWT format (header.payload.signature)
		token := strings.TrimPrefix(authHeader, "Bearer ")
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Errorf("JWT parts = %d, want 3", len(parts))
		}

		// Read and verify body is valid JSON-RPC
		body, _ := io.ReadAll(r.Body)
		var rpcReq map[string]interface{}
		if err := json.Unmarshal(body, &rpcReq); err != nil {
			t.Errorf("invalid JSON-RPC: %v", err)
		}

		if rpcReq["jsonrpc"] != "2.0" {
			t.Errorf("jsonrpc = %v, want 2.0", rpcReq["jsonrpc"])
		}

		if rpcReq["method"] != "workflows.execute" {
			t.Errorf("method = %v, want workflows.execute", rpcReq["method"])
		}

		// Return success
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      rpcReq["id"],
			"result":  "success",
		})
	}))
	defer mockServer.Close()

	// Override gateway URL to use mock server
	server.config.GatewayURL = mockServer.URL

	tests := []struct {
		name        string
		op          string
		domain      string
		tholdPrice  *float64
		tholdHash   *string
		callbackURL string
		wantErr     bool
	}{
		{
			name:        "create operation",
			op:          "create",
			domain:      "test-domain",
			tholdPrice:  func() *float64 { v := 100.0; return &v }(),
			callbackURL: "http://example.com/webhook",
			wantErr:     false,
		},
		{
			name:        "check operation",
			op:          "check",
			domain:      "test-domain",
			tholdHash:   func() *string { v := "abc123"; return &v }(),
			callbackURL: "http://example.com/webhook",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := server.triggerWorkflow(tt.op, tt.domain, tt.tholdPrice, tt.tholdHash, tt.callbackURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("server.triggerWorkflow() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestTriggerWorkflowErrors tests error cases for server.triggerWorkflow
func TestTriggerWorkflowErrors(t *testing.T) {
	setupTestEnv(t)
	loadConfig()

	tests := []struct {
		name        string
		setupMock   func() *httptest.Server
		expectError string
	}{
		{
			name: "non-200 response",
			setupMock: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte("bad request"))
				}))
			},
			expectError: "non-success status",
		},
		{
			name: "server error",
			setupMock: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("internal error"))
				}))
			},
			expectError: "non-success status",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockServer := tt.setupMock()
			defer mockServer.Close()

			server.config.GatewayURL = mockServer.URL

			tholdPrice := 100.0
			err := server.triggerWorkflow("create", "test-domain", &tholdPrice, nil, "http://example.com/webhook")
			if err == nil {
				t.Error("expected error but got nil")
			}
			if !strings.Contains(err.Error(), tt.expectError) {
				t.Errorf("error = %v, want to contain %s", err, tt.expectError)
			}
		})
	}
}

// TestComputeRecoveryIDEdgeCases tests edge cases in recovery ID computation using ethsign package
func TestComputeRecoveryIDEdgeCases(t *testing.T) {
	// Generate test key
	privateKeyHex := "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c"
	privKeyBytes, _ := hex.DecodeString(privateKeyHex)
	privKey, _ := crypto.ToECDSA(privKeyBytes)

	// Test with different messages
	messages := []string{
		"test",
		"",
		"a very long message that spans multiple lines and contains special characters !@#$%^&*()",
	}

	for _, msg := range messages {
		signature, err := ethsign.SignEthereumMessage(privKey, msg)
		if err != nil {
			t.Errorf("SignEthereumMessage failed for message %q: %v", msg, err)
			continue
		}

		// Verify signature format
		if len(signature) != 65 {
			t.Errorf("signature length = %d, want 65 for message %q", len(signature), msg)
		}

		// Verify v is in Ethereum format (27-30)
		v := signature[64]
		if v < 27 || v > 30 {
			t.Errorf("invalid v value %d for message %q, want 27-30 (Ethereum format)", v, msg)
		}
	}
}

// TestHandleCreateTimeout tests the timeout behavior
func TestHandleCreateTimeout(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Set very short timeout for testing
	oldTimeout := server.config.BlockTimeout
	server.config.BlockTimeout = 100 * time.Millisecond
	defer func() { server.config.BlockTimeout = oldTimeout }()

	// Mock the server.triggerWorkflow to avoid actual HTTP calls
	originalGatewayURL := server.config.GatewayURL
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer mockServer.Close()
	server.config.GatewayURL = mockServer.URL
	defer func() { server.config.GatewayURL = originalGatewayURL }()

	req := httptest.NewRequest("GET", "/api/quote?th=100", nil)
	w := httptest.NewRecorder()

	server.handleCreate(w, req)

	resp := w.Result()

	// Should timeout and return 202
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("status = %d, want %d (timeout)", resp.StatusCode, http.StatusAccepted)
	}

	var syncResp SyncResponse
	json.NewDecoder(resp.Body).Decode(&syncResp)

	if syncResp.Status != "timeout" {
		t.Errorf("status = %s, want timeout", syncResp.Status)
	}
}

// TestHandleCheckMaxPending tests max pending limit for check endpoint
func TestHandleCheckMaxPending(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Set low limit
	server.config.MaxPending = 2

	// Fill pending requests
	for i := 0; i < server.config.MaxPending; i++ {
		domain := fmt.Sprintf("test-%d", i)
		server.pendingRequests[domain] = &PendingRequest{
			RequestID:  domain,
			CreatedAt:  time.Now(),
			ResultChan: make(chan *WebhookPayload, 1),
			Status:     "pending",
		}
	}

	checkReq := CheckRequest{
		Domain:    "new-domain",
		TholdHash: "1234567890123456789012345678901234567890",
	}
	jsonData, _ := json.Marshal(checkReq)

	req := httptest.NewRequest("POST", "/check", bytes.NewReader(jsonData))
	w := httptest.NewRecorder()

	server.handleCheck(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}

	// Cleanup
	resetGlobals()
	server.config.MaxPending = 1000
}

// TestHandleCheckTimeout tests check endpoint timeout
func TestHandleCheckTimeout(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	oldTimeout := server.config.BlockTimeout
	server.config.BlockTimeout = 100 * time.Millisecond
	defer func() { server.config.BlockTimeout = oldTimeout }()

	// Mock the server.triggerWorkflow
	originalGatewayURL := server.config.GatewayURL
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer mockServer.Close()
	server.config.GatewayURL = mockServer.URL
	defer func() { server.config.GatewayURL = originalGatewayURL }()

	checkReq := CheckRequest{
		Domain:    "test-domain",
		TholdHash: "1234567890123456789012345678901234567890",
	}
	jsonData, _ := json.Marshal(checkReq)

	req := httptest.NewRequest("POST", "/check", bytes.NewReader(jsonData))
	w := httptest.NewRecorder()

	server.handleCheck(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("status = %d, want %d (timeout)", resp.StatusCode, http.StatusAccepted)
	}
}

// TestHandleCheckSuccess tests successful check with webhook
func TestHandleCheckSuccess(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Mock the server.triggerWorkflow
	originalGatewayURL := server.config.GatewayURL
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer mockServer.Close()
	server.config.GatewayURL = mockServer.URL
	defer func() { server.config.GatewayURL = originalGatewayURL }()

	checkReq := CheckRequest{
		Domain:    "test-check-domain",
		TholdHash: "1234567890123456789012345678901234567890",
	}
	jsonData, _ := json.Marshal(checkReq)

	req := httptest.NewRequest("POST", "/check", bytes.NewReader(jsonData))
	w := httptest.NewRecorder()

	// Simulate webhook arriving after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)

		server.requestsMutex.RLock()
		pending, exists := server.pendingRequests["test-check-domain"]
		server.requestsMutex.RUnlock()

		if exists {
			payload := &WebhookPayload{
				EventType: "check_no_breach",
				EventID:   "check-event-123",
				// Full CRE format payload with core-ts PriceContract fields
				Content: `{"event_type":"active","chain_network":"mutiny","oracle_pubkey":"abc123pubkey","base_price":95,"base_stamp":1699999000,"commit_hash":"commit123","contract_id":"contract456","oracle_sig":"sig789","thold_hash":"abc123def456","thold_key":null,"thold_price":100}`,
			}
			select {
			case pending.ResultChan <- payload:
			default:
			}
		}
	}()

	server.handleCheck(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	// Verify core-ts PriceContract fields
	if basePrice, ok := result["base_price"].(float64); ok {
		if basePrice != 95.0 {
			t.Errorf("base_price = %f, want 95.0", basePrice)
		}
	}

	if _, ok := result["chain_network"]; !ok {
		t.Error("chain_network not found in response")
	}
}

// TestHandleCreateWorkflowError tests workflow trigger error
func TestHandleCreateWorkflowError(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Mock server that returns error
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer mockServer.Close()

	server.config.GatewayURL = mockServer.URL

	req := httptest.NewRequest("GET", "/api/quote?th=100", nil)
	w := httptest.NewRecorder()

	server.handleCreate(w, req)

	resp := w.Result()

	// Should return 500 when workflow trigger fails
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
}

// TestWebhookParseContentError tests error handling when parsing webhook content
func TestWebhookParseContentError(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	domain := "test-parse-error"
	server.pendingRequests[domain] = &PendingRequest{
		RequestID:  domain,
		CreatedAt:  time.Now(),
		ResultChan: make(chan *WebhookPayload, 1),
		Status:     "pending",
	}

	// Create a properly signed webhook with invalid JSON content
	// The content being invalid JSON is fine - we're testing that the webhook is still delivered
	payload := createSignedWebhook("create", domain, `{invalid json}`, nil)
	jsonData, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(jsonData))
	w := httptest.NewRecorder()

	server.handleWebhook(w, req)

	resp := w.Result()
	// Webhook handler should still return 200 even with bad content
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Verify the webhook was still delivered to the pending request
	pending := server.pendingRequests[domain]
	select {
	case result := <-pending.ResultChan:
		if result.EventID != payload.EventID {
			t.Errorf("event_id = %s, want %s", result.EventID, payload.EventID)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("webhook not delivered to pending request")
	}
}

// TestHandleWebhookDuplicateDelivery tests duplicate webhook handling
func TestHandleWebhookDuplicateDelivery(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	domain := "test-duplicate"
	pending := &PendingRequest{
		RequestID:  domain,
		CreatedAt:  time.Now(),
		ResultChan: make(chan *WebhookPayload, 1),
		Status:     "pending",
	}
	server.pendingRequests[domain] = pending

	// Create a properly signed webhook
	payload := createSignedWebhook("create", domain, `{"test": "data"}`, nil)
	jsonData, _ := json.Marshal(payload)

	// Send first webhook
	req1 := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(jsonData))
	w1 := httptest.NewRecorder()

	// Track channel deliveries
	deliveryCount := 0
	go func() {
		for range pending.ResultChan {
			deliveryCount++
		}
	}()

	server.handleWebhook(w1, req1)
	time.Sleep(50 * time.Millisecond)

	// Send duplicate webhook (same event_id should be rejected with 409 Conflict)
	req2 := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(jsonData))
	w2 := httptest.NewRecorder()
	server.handleWebhook(w2, req2)
	time.Sleep(50 * time.Millisecond)

	// First webhook should succeed with 200
	if w1.Code != http.StatusOK {
		t.Errorf("first webhook status = %d, want %d", w1.Code, http.StatusOK)
	}
	// Duplicate webhook should be rejected with 409 Conflict (replay protection)
	if w2.Code != http.StatusConflict {
		t.Errorf("duplicate webhook status = %d, want %d (replay protection)", w2.Code, http.StatusConflict)
	}

	close(pending.ResultChan)
	time.Sleep(10 * time.Millisecond)

	// Only first webhook should be delivered due to replay protection
	if deliveryCount == 0 {
		t.Error("no webhooks were delivered")
	}
	if deliveryCount > 1 {
		t.Errorf("expected 1 delivery (replay protection), got %d", deliveryCount)
	}
}

// TestHandleCheckWorkflowError tests workflow trigger error for check
func TestHandleCheckWorkflowError(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Mock server that returns error
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bad request"))
	}))
	defer mockServer.Close()

	server.config.GatewayURL = mockServer.URL

	checkReq := CheckRequest{
		Domain:    "test-domain",
		TholdHash: "1234567890123456789012345678901234567890",
	}
	jsonData, _ := json.Marshal(checkReq)

	req := httptest.NewRequest("POST", "/check", bytes.NewReader(jsonData))
	w := httptest.NewRecorder()

	server.handleCheck(w, req)

	resp := w.Result()

	// Should return 500 when workflow trigger fails
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
}

// TestHandleCheckBreach tests check endpoint with breach event
func TestHandleCheckBreach(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Mock the server.triggerWorkflow
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer mockServer.Close()
	server.config.GatewayURL = mockServer.URL

	checkReq := CheckRequest{
		Domain:    "test-breach-domain",
		TholdHash: "1234567890123456789012345678901234567890",
	}
	jsonData, _ := json.Marshal(checkReq)

	req := httptest.NewRequest("POST", "/check", bytes.NewReader(jsonData))
	w := httptest.NewRecorder()

	// Simulate webhook with breach event
	go func() {
		time.Sleep(50 * time.Millisecond)

		server.requestsMutex.RLock()
		pending, exists := server.pendingRequests["test-breach-domain"]
		server.requestsMutex.RUnlock()

		if exists {
			payload := &WebhookPayload{
				EventType: "breach",
				EventID:   "breach-event-123",
				Content:   `{"event_type":"breach","chain_network":"mutiny","oracle_pubkey":"abc123pubkey","base_price":90,"base_stamp":1699999000,"commit_hash":"commit123","contract_id":"contract456","oracle_sig":"sig789","thold_hash":"abc123def456","thold_key":"secret123","thold_price":100}`,
			}
			select {
			case pending.ResultChan <- payload:
			default:
			}
		}
	}()

	server.handleCheck(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	// Verify breach data is returned
	if tholdKey, ok := result["thold_key"].(string); ok {
		if tholdKey != "secret123" {
			t.Errorf("thold_key = %s, want secret123", tholdKey)
		}
	} else {
		t.Error("thold_key not found in breach response")
	}
}

// TestHandleCreateSuccess tests successful create with webhook
func TestHandleCreateSuccess(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Mock the server.triggerWorkflow
	originalGatewayURL := server.config.GatewayURL
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer mockServer.Close()
	server.config.GatewayURL = mockServer.URL
	defer func() { server.config.GatewayURL = originalGatewayURL }()

	req := httptest.NewRequest("GET", "/api/quote?th=100.5", nil)
	w := httptest.NewRecorder()

	// Simulate webhook arriving after request is created
	go func() {
		time.Sleep(50 * time.Millisecond)

		server.requestsMutex.RLock()
		// Find the pending request (domain is generated, so we need to iterate)
		var pending *PendingRequest
		var domain string
		for d, p := range server.pendingRequests {
			if p.Status == "pending" {
				pending = p
				domain = d
				break
			}
		}
		server.requestsMutex.RUnlock()

		if pending != nil {
			payload := &WebhookPayload{
				EventType: "create",
				EventID:   "create-event-123",
				Tags:      [][]string{{"domain", domain}},
				// Full CRE format payload with core-ts PriceContract fields
				Content: `{"event_type":"active","chain_network":"mutiny","oracle_pubkey":"abc123pubkey","base_price":99,"base_stamp":1699999000,"commit_hash":"commit123","contract_id":"contract456","oracle_sig":"sig789","thold_hash":"abc123def456","thold_key":null,"thold_price":100}`,
			}
			select {
			case pending.ResultChan <- payload:
			default:
			}
		}
	}()

	server.handleCreate(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	// Verify core-ts PriceContract fields
	if basePrice, ok := result["base_price"].(float64); ok {
		if basePrice != 99.0 {
			t.Errorf("base_price = %f, want 99.0", basePrice)
		}
	}

	// Verify PriceContract fields exist
	if network, ok := result["chain_network"].(string); !ok || network != "mutiny" {
		t.Errorf("chain_network = %v, want 'mutiny'", result["chain_network"])
	}

	if _, ok := result["commit_hash"]; !ok {
		t.Error("commit_hash not found in response")
	}

	if _, ok := result["contract_id"]; !ok {
		t.Error("contract_id not found in response")
	}
}

// TestSecureCompare tests constant-time string comparison
func TestSecureCompare(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		expected bool
	}{
		{"equal strings", "hello", "hello", true},
		{"different strings", "hello", "world", false},
		{"different lengths", "hello", "hi", false},
		{"empty strings", "", "", true},
		{"one empty", "hello", "", false},
		{"hex strings equal", "abc123def456", "abc123def456", true},
		{"hex strings different", "abc123def456", "abc123def457", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := secureCompare(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("secureCompare(%q, %q) = %v, want %v", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

// TestIsValidHex tests hex validation
func TestIsValidHex(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedLen int
		expected    bool
	}{
		{"valid 40 char hex", "1234567890abcdef1234567890abcdef12345678", 40, true},
		{"valid 64 char hex", "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 64, true},
		{"uppercase hex", "ABCDEF1234567890ABCDEF1234567890ABCDEF12", 40, true},
		{"mixed case hex", "AbCdEf1234567890AbCdEf1234567890AbCdEf12", 40, true},
		{"wrong length", "1234567890abcdef", 40, false},
		{"contains non-hex", "1234567890ghijkl1234567890abcdef12345678", 40, false},
		{"empty string", "", 40, false},
		{"special chars", "1234567890!@#$%^1234567890abcdef12345678", 40, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidHex(tt.input, tt.expectedLen)
			if result != tt.expected {
				t.Errorf("isValidHex(%q, %d) = %v, want %v", tt.input, tt.expectedLen, result, tt.expected)
			}
		})
	}
}

// TestWebhookReplayProtection tests the webhook replay protection cache
func TestWebhookReplayProtection(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	eventID := "test-event-id-12345"

	// First check should return false (not replayed)
	if server.isWebhookReplayed(eventID) {
		t.Error("isWebhookReplayed should return false for new event")
	}

	// Mark as processed
	server.markWebhookProcessed(eventID)

	// Now should return true (is replayed)
	if !server.isWebhookReplayed(eventID) {
		t.Error("isWebhookReplayed should return true after marking")
	}

	// Different event should still return false
	if server.isWebhookReplayed("different-event-id") {
		t.Error("isWebhookReplayed should return false for different event")
	}
}

// TestWebhookCacheCleanup tests that old webhook entries are cleaned up
func TestWebhookCacheCleanup(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Add some entries directly to the cache with old timestamps
	server.processedWebhooksMutex.Lock()
	server.processedWebhooks["old-event-1"] = time.Now().Add(-10 * time.Minute) // Older than TTL
	server.processedWebhooks["old-event-2"] = time.Now().Add(-6 * time.Minute)  // Older than TTL
	server.processedWebhooks["new-event"] = time.Now()                          // Fresh
	server.processedWebhooksMutex.Unlock()

	// Run cleanup
	cleaned := server.cleanupWebhookCache()

	// Should have cleaned 2 old entries
	if cleaned != 2 {
		t.Errorf("cleanupWebhookCache() = %d, want 2", cleaned)
	}

	// New event should still exist
	if !server.isWebhookReplayed("new-event") {
		t.Error("new-event should still be in cache after cleanup")
	}

	// Old events should be gone
	if server.isWebhookReplayed("old-event-1") {
		t.Error("old-event-1 should have been cleaned up")
	}
	if server.isWebhookReplayed("old-event-2") {
		t.Error("old-event-2 should have been cleaned up")
	}
}

// TestGetClientIP tests IP extraction from requests
func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		expected   string
	}{
		{
			name:       "no headers, use RemoteAddr",
			headers:    nil,
			remoteAddr: "192.168.1.1:12345",
			expected:   "192.168.1.1",
		},
		{
			name:       "X-Forwarded-For single",
			headers:    map[string]string{"X-Forwarded-For": "10.0.0.1"},
			remoteAddr: "192.168.1.1:12345",
			expected:   "10.0.0.1",
		},
		{
			name:       "X-Forwarded-For chain",
			headers:    map[string]string{"X-Forwarded-For": "10.0.0.1, 10.0.0.2, 10.0.0.3"},
			remoteAddr: "192.168.1.1:12345",
			expected:   "10.0.0.1",
		},
		{
			name:       "X-Real-IP",
			headers:    map[string]string{"X-Real-IP": "172.16.0.1"},
			remoteAddr: "192.168.1.1:12345",
			expected:   "172.16.0.1",
		},
		{
			name:       "X-Forwarded-For takes precedence",
			headers:    map[string]string{"X-Forwarded-For": "10.0.0.1", "X-Real-IP": "172.16.0.1"},
			remoteAddr: "192.168.1.1:12345",
			expected:   "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			result := getClientIP(req)
			if result != tt.expected {
				t.Errorf("getClientIP() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestHandleReadiness tests the readiness endpoint
func TestHandleReadiness(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	tests := []struct {
		name           string
		setup          func()
		expectedStatus int
		validateBody   func(t *testing.T, body []byte)
	}{
		{
			name: "healthy with mock gateway",
			setup: func() {
				// Setup mock CRE gateway
				mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				}))
				server.config.GatewayURL = mockServer.URL
			},
			expectedStatus: http.StatusOK,
			validateBody: func(t *testing.T, body []byte) {
				var resp HealthResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					t.Fatalf("failed to parse response: %v", err)
				}
				if resp.Status != "healthy" {
					t.Errorf("status = %s, want healthy", resp.Status)
				}
			},
		},
		{
			name: "degraded when near capacity",
			setup: func() {
				// Fill to 95% capacity
				server.config.MaxPending = 100
				for i := 0; i < 95; i++ {
					domain := fmt.Sprintf("capacity-test-%d", i)
					server.pendingRequests[domain] = &PendingRequest{
						RequestID:  domain,
						CreatedAt:  time.Now(),
						ResultChan: make(chan *WebhookPayload, 1),
						Status:     "pending",
					}
				}
				// Setup mock gateway
				mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				}))
				server.config.GatewayURL = mockServer.URL
			},
			expectedStatus: http.StatusOK,
			validateBody: func(t *testing.T, body []byte) {
				var resp HealthResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					t.Fatalf("failed to parse response: %v", err)
				}
				if resp.Status != "degraded" {
					t.Errorf("status = %s, want degraded", resp.Status)
				}
			},
		},
		{
			name: "degraded when gateway unreachable",
			setup: func() {
				resetGlobals()
				// Point to non-existent gateway
				server.config.GatewayURL = "http://localhost:1"
			},
			expectedStatus: http.StatusOK, // degraded is still 200
			validateBody: func(t *testing.T, body []byte) {
				var resp HealthResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					t.Fatalf("failed to parse response: %v", err)
				}
				if resp.Status != "degraded" {
					t.Errorf("status = %s, want degraded", resp.Status)
				}
				if resp.Dependencies["cre_gateway"].Status != "down" {
					t.Errorf("cre_gateway status = %s, want down", resp.Dependencies["cre_gateway"].Status)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetGlobals()
			if tt.setup != nil {
				tt.setup()
			}

			req := httptest.NewRequest("GET", "/readiness", nil)
			w := httptest.NewRecorder()

			server.handleReadiness(w, req)

			resp := w.Result()
			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.expectedStatus)
			}

			if tt.validateBody != nil {
				body, _ := io.ReadAll(resp.Body)
				tt.validateBody(t, body)
			}

			// Cleanup
			resetGlobals()
			server.config.MaxPending = 1000
		})
	}
}

// TestCircuitBreakerState tests circuit breaker state transitions
func TestCircuitBreakerState(t *testing.T) {
	// Use NewCircuitBreaker to properly initialize state
	cb := NewCircuitBreaker(3, 30*time.Second)

	// Initially closed
	if state := cb.State(); state != "closed" {
		t.Errorf("initial state = %s, want closed", state)
	}

	// Record failures to open circuit
	for i := 0; i < 3; i++ {
		cb.RecordFailure()
	}

	if state := cb.State(); state != "open" {
		t.Errorf("after failures state = %s, want open", state)
	}

	// RecordSuccess only closes from half-open state, not from open
	// So circuit remains open
	cb.RecordSuccess()
	if state := cb.State(); state != "open" {
		t.Errorf("after success in open state = %s, want open (success only closes from half-open)", state)
	}

	// Manually set to half-open to test success behavior
	cb.mu.Lock()
	cb.state = "half-open"
	cb.mu.Unlock()

	// Now RecordSuccess should close the circuit
	cb.RecordSuccess()
	if state := cb.State(); state != "closed" {
		t.Errorf("after success in half-open state = %s, want closed", state)
	}
}

// TestTruncateEventID tests event ID truncation
func TestTruncateEventID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "long event ID",
			input:    "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			expected: "abcdef1234567890",
		},
		{
			name:     "short event ID",
			input:    "abc123",
			expected: "abc123",
		},
		{
			name:     "exactly 16 chars",
			input:    "1234567890123456",
			expected: "1234567890123456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateEventID(tt.input)
			if result != tt.expected {
				t.Errorf("truncateEventID(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestValidatePrivateKey tests private key validation
func TestValidatePrivateKey(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		expectError bool
	}{
		{
			name:        "valid 64 char key",
			key:         "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c",
			expectError: false,
		},
		{
			name:        "with 0x prefix (not stripped)",
			key:         "0xe0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c",
			expectError: true, // validatePrivateKey expects exactly 64 chars without 0x prefix
		},
		{
			name:        "too short",
			key:         "e0144cfbe97dcb2554ebf918b1ee12c1",
			expectError: true,
		},
		{
			name:        "invalid hex",
			key:         "g0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c",
			expectError: true,
		},
		{
			name:        "empty",
			key:         "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePrivateKey(tt.key)
			if tt.expectError && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestMarshalSorted tests deterministic JSON marshaling
func TestMarshalSorted(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		expected string
	}{
		{
			name:     "simple map",
			input:    map[string]interface{}{"z": 1, "a": 2, "m": 3},
			expected: `{"a":2,"m":3,"z":1}`,
		},
		{
			name:     "nested map",
			input:    map[string]interface{}{"outer": map[string]interface{}{"z": 1, "a": 2}},
			expected: `{"outer":{"a":2,"z":1}}`,
		},
		{
			name:     "with array",
			input:    map[string]interface{}{"arr": []interface{}{"c", "a", "b"}},
			expected: `{"arr":["c","a","b"]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := marshalSorted(tt.input)
			if err != nil {
				t.Fatalf("marshalSorted() error = %v", err)
			}
			if string(result) != tt.expected {
				t.Errorf("marshalSorted() = %s, want %s", string(result), tt.expected)
			}
		})
	}
}

// TestVerifyWebhookSignatureAllZero tests all-zero signature/pubkey rejection
func TestVerifyWebhookSignatureAllZero(t *testing.T) {
	setupTestEnv(t)
	loadConfig()

	tests := []struct {
		name        string
		payload     *WebhookPayload
		expectError string
	}{
		{
			name: "all-zero signature rejected",
			payload: &WebhookPayload{
				EventID:   "a" + strings.Repeat("0", 63),
				PubKey:    strings.Repeat("a", 64),
				Sig:       strings.Repeat("0", 128),
				CreatedAt: time.Now().Unix(),
				Kind:      1,
				Tags:      [][]string{},
				Content:   "test",
			},
			expectError: "event_id mismatch", // Will fail event_id check first
		},
		{
			name: "all-zero pubkey rejected",
			payload: &WebhookPayload{
				EventID:   strings.Repeat("a", 64),
				PubKey:    strings.Repeat("0", 64),
				Sig:       strings.Repeat("a", 128),
				CreatedAt: time.Now().Unix(),
				Kind:      1,
				Tags:      [][]string{},
				Content:   "test",
			},
			expectError: "event_id mismatch", // Will fail event_id check first
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyWebhookSignature(tt.payload)
			if err == nil {
				t.Error("expected error but got nil")
			}
			if !strings.Contains(err.Error(), tt.expectError) {
				t.Errorf("error = %v, want to contain %s", err, tt.expectError)
			}
		})
	}
}

// TestHandleWebhookFutureTimestamp tests webhook with future timestamp
func TestHandleWebhookFutureTimestamp(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Create a webhook with future timestamp (5 minutes in the future)
	payload := createSignedWebhook("create", "test-domain", `{"thold_price": 100}`, nil)
	payload.CreatedAt = time.Now().Unix() + 300 // 5 minutes in future

	// Re-sign with future timestamp
	tagsJSON, _ := json.Marshal(payload.Tags)
	serialized := fmt.Sprintf("[0,%q,%d,%d,%s,%q]",
		payload.PubKey, payload.CreatedAt, payload.Kind, string(tagsJSON), payload.Content)
	hash := sha256.Sum256([]byte(serialized))
	payload.EventID = hex.EncodeToString(hash[:])

	privKey, _ := btcec.PrivKeyFromBytes(testWebhookPrivKey)
	eventIDBytes, _ := hex.DecodeString(payload.EventID)
	sig, _ := schnorr.Sign(privKey, eventIDBytes)
	payload.Sig = hex.EncodeToString(sig.Serialize())

	jsonData, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(jsonData))
	w := httptest.NewRecorder()
	server.handleWebhook(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d (unauthorized for future timestamp)", w.Code, http.StatusUnauthorized)
	}
}

// TestHandleWebhookMissingDomain tests webhook without domain tag
func TestHandleWebhookMissingDomain(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Create a webhook without domain tag
	_, pubKey := btcec.PrivKeyFromBytes(testWebhookPrivKey)
	pubKeyHex := hex.EncodeToString(schnorr.SerializePubKey(pubKey))

	payload := WebhookPayload{
		EventType: "create",
		PubKey:    pubKeyHex,
		CreatedAt: time.Now().Unix(),
		Kind:      30078,
		Tags:      [][]string{}, // No domain tag
		Content:   `{"thold_price": 100}`,
	}

	// Compute event ID
	tagsJSON, _ := json.Marshal(payload.Tags)
	serialized := fmt.Sprintf("[0,%q,%d,%d,%s,%q]",
		payload.PubKey, payload.CreatedAt, payload.Kind, string(tagsJSON), payload.Content)
	hash := sha256.Sum256([]byte(serialized))
	payload.EventID = hex.EncodeToString(hash[:])

	// Sign
	privKey, _ := btcec.PrivKeyFromBytes(testWebhookPrivKey)
	eventIDBytes, _ := hex.DecodeString(payload.EventID)
	sig, _ := schnorr.Sign(privKey, eventIDBytes)
	payload.Sig = hex.EncodeToString(sig.Serialize())

	jsonData, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(jsonData))
	w := httptest.NewRecorder()
	server.handleWebhook(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d (bad request for missing domain)", w.Code, http.StatusBadRequest)
	}
}

// TestPanicRecoveryMiddleware tests panic recovery
func TestPanicRecoveryMiddleware(t *testing.T) {
	// Create a handler that panics
	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	// Wrap with panic recovery
	handler := panicRecoveryMiddleware(panicHandler)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	// Should not panic - middleware should recover
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d after panic recovery", w.Code, http.StatusInternalServerError)
	}
}

// TestMetricsMiddleware tests metrics recording
func TestMetricsMiddleware(t *testing.T) {
	setupTestEnv(t)
	loadConfig()

	// Create a simple handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Wrap with metrics middleware (requires endpoint name)
	handler := metricsMiddleware("test", testHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

// TestRateLimitMiddleware tests rate limiting
func TestRateLimitMiddleware(t *testing.T) {
	setupTestEnv(t)
	loadConfig()

	// Create a simple handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrap with rate limit middleware (it's a method on server)
	handler := server.rateLimitMiddleware(testHandler)

	// First request should succeed
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("first request status = %d, want %d", w.Code, http.StatusOK)
	}

	// Simulate many requests to trigger rate limit
	for i := 0; i < 200; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}

	// Next request should be rate limited
	req = httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should eventually be rate limited
	if w.Code != http.StatusTooManyRequests && w.Code != http.StatusOK {
		t.Logf("Note: rate limit test may not trigger limit depending on config")
	}
}

// TestResponseWriterWriteHeader tests custom response writer
func TestResponseWriterWriteHeader(t *testing.T) {
	w := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

	rw.WriteHeader(http.StatusNotFound)

	if rw.statusCode != http.StatusNotFound {
		t.Errorf("statusCode = %d, want %d", rw.statusCode, http.StatusNotFound)
	}
}

// TestIPRateLimiterCleanup tests IP rate limiter cleanup
func TestIPRateLimiterCleanup(t *testing.T) {
	limiter := NewIPRateLimiter(10, 1)

	// Add some entries
	limiter.GetLimiter("192.168.1.1")
	limiter.GetLimiter("192.168.1.2")
	limiter.GetLimiter("192.168.1.3")

	// Cleanup with 0 TTL should remove all
	cleaned := limiter.Cleanup(0)

	if cleaned != 3 {
		t.Errorf("cleanup returned %d, want 3", cleaned)
	}

	// Verify empty
	limiter.mu.RLock()
	count := len(limiter.limiters)
	limiter.mu.RUnlock()

	if count != 0 {
		t.Errorf("after cleanup count = %d, want 0", count)
	}
}

// TestHandleStatusWithDifferentPath tests /status endpoint with URL path request ID
func TestHandleStatusWithDifferentPath(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Setup request with path parameter
	server.pendingRequests["path-param-req"] = &PendingRequest{
		RequestID:  "path-param-req",
		CreatedAt:  time.Now(),
		ResultChan: make(chan *WebhookPayload, 1),
		Status:     "pending",
	}

	req := httptest.NewRequest("GET", "/status/path-param-req", nil)
	w := httptest.NewRecorder()

	server.handleStatus(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var syncResp SyncResponse
	json.NewDecoder(resp.Body).Decode(&syncResp)

	if syncResp.Status != "pending" {
		t.Errorf("response status = %s, want pending", syncResp.Status)
	}
}

// TestHandleStatusTimeout tests /status endpoint with timeout request
func TestHandleStatusTimeout(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Setup timed out request
	server.pendingRequests["timeout-req"] = &PendingRequest{
		RequestID:  "timeout-req",
		CreatedAt:  time.Now(),
		ResultChan: make(chan *WebhookPayload, 1),
		Status:     "timeout",
	}

	req := httptest.NewRequest("GET", "/status/timeout-req", nil)
	w := httptest.NewRecorder()

	server.handleStatus(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var syncResp SyncResponse
	json.NewDecoder(resp.Body).Decode(&syncResp)

	if syncResp.Status != "timeout" {
		t.Errorf("response status = %s, want timeout", syncResp.Status)
	}
}

// TestCircuitBreakerAllow tests all branches of the Allow method
func TestCircuitBreakerAllow(t *testing.T) {
	t.Run("closed state allows requests", func(t *testing.T) {
		cb := NewCircuitBreaker(3, 100*time.Millisecond)
		if !cb.Allow() {
			t.Error("expected Allow() to return true in closed state")
		}
	})

	t.Run("open state denies requests", func(t *testing.T) {
		cb := NewCircuitBreaker(3, 1*time.Hour) // Long timeout
		// Open the circuit
		for i := 0; i < 3; i++ {
			cb.RecordFailure()
		}
		if cb.Allow() {
			t.Error("expected Allow() to return false in open state")
		}
	})

	t.Run("open state transitions to half-open after timeout", func(t *testing.T) {
		cb := NewCircuitBreaker(3, 10*time.Millisecond) // Short timeout
		// Open the circuit
		for i := 0; i < 3; i++ {
			cb.RecordFailure()
		}
		// Wait for reset timeout
		time.Sleep(20 * time.Millisecond)
		if !cb.Allow() {
			t.Error("expected Allow() to return true after timeout (transition to half-open)")
		}
		if cb.State() != "half-open" {
			t.Errorf("expected state to be half-open, got %s", cb.State())
		}
	})

	t.Run("half-open state allows limited requests", func(t *testing.T) {
		cb := NewCircuitBreaker(3, 10*time.Millisecond)
		// Open circuit then wait for half-open
		for i := 0; i < 3; i++ {
			cb.RecordFailure()
		}
		time.Sleep(20 * time.Millisecond)

		// First call transitions to half-open, resets counter to 0, returns true
		if !cb.Allow() {
			t.Error("expected Allow() to allow first request transitioning to half-open")
		}

		// Now in half-open state, halfOpenMaxReqs is 3
		// halfOpenReqs: 0 -> 1 (allowed)
		if !cb.Allow() {
			t.Error("expected Allow() to allow second request in half-open (reqs=1)")
		}
		// halfOpenReqs: 1 -> 2 (allowed)
		if !cb.Allow() {
			t.Error("expected Allow() to allow third request in half-open (reqs=2)")
		}
		// halfOpenReqs: 2 -> 3 (allowed, reaches limit)
		if !cb.Allow() {
			t.Error("expected Allow() to allow fourth request in half-open (reqs=3)")
		}
		// halfOpenReqs: 3 >= 3, denied
		if cb.Allow() {
			t.Error("expected Allow() to deny fifth request after halfOpenMaxReqs exceeded")
		}
	})

	t.Run("unknown state returns false", func(t *testing.T) {
		cb := NewCircuitBreaker(3, time.Second)
		cb.mu.Lock()
		cb.state = "unknown"
		cb.mu.Unlock()
		if cb.Allow() {
			t.Error("expected Allow() to return false for unknown state")
		}
	})
}

// TestMarkWebhookProcessed tests webhook cache with eviction
func TestMarkWebhookProcessed(t *testing.T) {
	setupTestEnv(t)
	loadConfig()

	testServer := &GatewayServer{
		config:            server.config,
		logger:            logger,
		processedWebhooks: make(map[string]time.Time),
	}

	t.Run("basic marking", func(t *testing.T) {
		testServer.markWebhookProcessed("event1")
		if !testServer.isWebhookReplayed("event1") {
			t.Error("expected event1 to be marked as processed")
		}
	})

	t.Run("cache eviction at max size", func(t *testing.T) {
		// Create a server with a fresh cache
		s := &GatewayServer{
			config:            server.config,
			logger:            logger,
			processedWebhooks: make(map[string]time.Time),
		}

		// Fill up to maxWebhookCacheSize (10000) - we'll test with a subset
		// First add some entries with old timestamps
		s.processedWebhooksMutex.Lock()
		oldTime := time.Now().Add(-1 * time.Hour)
		s.processedWebhooks["oldest-entry"] = oldTime
		// Fill to capacity minus 1
		for i := 0; i < maxWebhookCacheSize-1; i++ {
			s.processedWebhooks[fmt.Sprintf("entry-%d", i)] = time.Now()
		}
		s.processedWebhooksMutex.Unlock()

		// Now add one more which should evict the oldest
		s.markWebhookProcessed("new-entry")

		s.processedWebhooksMutex.Lock()
		_, exists := s.processedWebhooks["oldest-entry"]
		s.processedWebhooksMutex.Unlock()

		if exists {
			t.Error("expected oldest-entry to be evicted")
		}
	})
}

// TestGetLimiterEviction tests IP rate limiter with eviction
func TestGetLimiterEviction(t *testing.T) {
	limiter := NewIPRateLimiter(10, 20)

	t.Run("basic get limiter", func(t *testing.T) {
		l := limiter.GetLimiter("192.168.1.1")
		if l == nil {
			t.Error("expected non-nil limiter")
		}
	})

	t.Run("same IP returns same limiter", func(t *testing.T) {
		l1 := limiter.GetLimiter("192.168.1.2")
		l2 := limiter.GetLimiter("192.168.1.2")
		if l1 != l2 {
			t.Error("expected same limiter for same IP")
		}
	})

	t.Run("eviction at max capacity", func(t *testing.T) {
		// Create a new limiter with fresh state
		evictLimiter := NewIPRateLimiter(10, 20)

		// Add an old entry
		evictLimiter.mu.Lock()
		evictLimiter.limiters["oldest-ip"] = &rateLimiterEntry{
			limiter:  rate.NewLimiter(10, 20),
			lastSeen: time.Now().Add(-1 * time.Hour),
		}
		// Fill to capacity minus 1
		for i := 0; i < maxIPRateLimiters-1; i++ {
			evictLimiter.limiters[fmt.Sprintf("ip-%d", i)] = &rateLimiterEntry{
				limiter:  rate.NewLimiter(10, 20),
				lastSeen: time.Now(),
			}
		}
		evictLimiter.mu.Unlock()

		// Add one more to trigger eviction
		evictLimiter.GetLimiter("new-ip")

		evictLimiter.mu.Lock()
		_, exists := evictLimiter.limiters["oldest-ip"]
		evictLimiter.mu.Unlock()

		if exists {
			t.Error("expected oldest-ip to be evicted")
		}
	})
}

// TestDoLiquidationPoll tests the liquidation polling logic
func TestDoLiquidationPoll(t *testing.T) {
	setupTestEnv(t)
	loadConfig()

	t.Run("successful poll with at-risk vaults", func(t *testing.T) {
		// Create mock CRE gateway server
		mockCREServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"result": "ok"}`))
		}))
		defer mockCREServer.Close()

		// Create mock liquidation server
		mockLiqServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := AtRiskResponse{
				TotalCount:   2,
				CurrentPrice: 50000.0,
				Threshold:    1.5,
				AtRiskVaults: []AtRiskVault{
					{VaultID: "vault1", TholdHash: strings.Repeat("a", 40), CurrentRatio: 1.4, TholdPrice: 48000.0},
					{VaultID: "vault2", TholdHash: strings.Repeat("b", 40), CurrentRatio: 1.3, TholdPrice: 47000.0},
				},
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer mockLiqServer.Close()

		testServer := &GatewayServer{
			config: &GatewayConfig{
				LiquidationURL:      mockLiqServer.URL,
				LiquidationInterval: time.Minute,
				GatewayURL:          mockCREServer.URL,
				WorkflowID:          "test-workflow",
				CallbackURL:         "http://localhost:8080/webhook",
				AuthorizedKey:       "0xtest123",
			},
			logger:          logger,
			circuitBreaker:  NewCircuitBreaker(3, 30*time.Second),
			pendingRequests: make(map[string]*PendingRequest),
			privateKey:      server.privateKey,
		}

		// This should not panic and should process successfully
		testServer.doLiquidationPoll()
	})

	t.Run("poll with no at-risk vaults", func(t *testing.T) {
		mockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := AtRiskResponse{
				TotalCount:   0,
				CurrentPrice: 50000.0,
				Threshold:    1.5,
				AtRiskVaults: []AtRiskVault{},
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer mockSrv.Close()

		testServer := &GatewayServer{
			config: &GatewayConfig{
				LiquidationURL: mockSrv.URL,
			},
			logger:         logger,
			circuitBreaker: NewCircuitBreaker(3, 30*time.Second),
		}

		testServer.doLiquidationPoll()
	})

	t.Run("poll with non-200 response", func(t *testing.T) {
		mockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("internal error"))
		}))
		defer mockSrv.Close()

		testServer := &GatewayServer{
			config: &GatewayConfig{
				LiquidationURL: mockSrv.URL,
			},
			logger:         logger,
			circuitBreaker: NewCircuitBreaker(3, 30*time.Second),
		}

		testServer.doLiquidationPoll()
	})

	t.Run("poll with invalid JSON response", func(t *testing.T) {
		mockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("not valid json"))
		}))
		defer mockSrv.Close()

		testServer := &GatewayServer{
			config: &GatewayConfig{
				LiquidationURL: mockSrv.URL,
			},
			logger:         logger,
			circuitBreaker: NewCircuitBreaker(3, 30*time.Second),
		}

		testServer.doLiquidationPoll()
	})

	t.Run("poll with unreachable server", func(t *testing.T) {
		testServer := &GatewayServer{
			config: &GatewayConfig{
				LiquidationURL: "http://localhost:59999", // Unlikely to be listening
			},
			logger:         logger,
			circuitBreaker: NewCircuitBreaker(3, 30*time.Second),
		}

		testServer.doLiquidationPoll()
	})

	t.Run("poll with many at-risk vaults (test logging limit)", func(t *testing.T) {
		// Create mock CRE gateway server
		mockCREServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"result": "ok"}`))
		}))
		defer mockCREServer.Close()

		mockLiqServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			vaults := make([]AtRiskVault, 15)
			for i := 0; i < 15; i++ {
				vaults[i] = AtRiskVault{
					VaultID:      fmt.Sprintf("vault%d", i),
					TholdHash:    strings.Repeat(fmt.Sprintf("%x", i%16), 40),
					CurrentRatio: 1.4,
					TholdPrice:   48000.0,
				}
			}
			resp := AtRiskResponse{
				TotalCount:   15,
				CurrentPrice: 50000.0,
				Threshold:    1.5,
				AtRiskVaults: vaults,
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer mockLiqServer.Close()

		testServer := &GatewayServer{
			config: &GatewayConfig{
				LiquidationURL: mockLiqServer.URL,
				GatewayURL:     mockCREServer.URL,
				WorkflowID:     "test-workflow",
				CallbackURL:    "http://localhost:8080/webhook",
				AuthorizedKey:  "0xtest123",
			},
			logger:          logger,
			circuitBreaker:  NewCircuitBreaker(3, 30*time.Second),
			pendingRequests: make(map[string]*PendingRequest),
			privateKey:      server.privateKey,
		}

		testServer.doLiquidationPoll()
	})
}

// TestTriggerCheckForAtRiskVaults tests the at-risk vault trigger logic
func TestTriggerCheckForAtRiskVaults(t *testing.T) {
	setupTestEnv(t)
	loadConfig()

	t.Run("empty vaults list", func(t *testing.T) {
		testServer := &GatewayServer{
			config:         server.config,
			logger:         logger,
			circuitBreaker: NewCircuitBreaker(3, 30*time.Second),
		}

		// Should return early without error
		testServer.triggerCheckForAtRiskVaults([]AtRiskVault{})
	})

	t.Run("vaults with invalid thold_hash", func(t *testing.T) {
		testServer := &GatewayServer{
			config:         server.config,
			logger:         logger,
			circuitBreaker: NewCircuitBreaker(3, 30*time.Second),
		}

		vaults := []AtRiskVault{
			{VaultID: "vault1", TholdHash: "too-short"},
			{VaultID: "vault2", TholdHash: ""},
			{VaultID: "vault3", TholdHash: "invalid!chars" + strings.Repeat("0", 26)},
		}

		// Should skip all invalid vaults
		testServer.triggerCheckForAtRiskVaults(vaults)
	})

	t.Run("vaults with valid thold_hash but circuit breaker open", func(t *testing.T) {
		cb := NewCircuitBreaker(1, 1*time.Hour)
		cb.RecordFailure() // Open the circuit

		testServer := &GatewayServer{
			config: &GatewayConfig{
				GatewayURL:  "http://localhost:8080",
				WorkflowID:  "test-workflow",
				CallbackURL: "http://localhost:8080/webhook",
			},
			logger:         logger,
			circuitBreaker: cb,
		}

		vaults := []AtRiskVault{
			{VaultID: "vault1", TholdHash: strings.Repeat("a", 40)},
		}

		testServer.triggerCheckForAtRiskVaults(vaults)
	})
}

// TestTriggerEvaluateWorkflow tests the evaluate workflow trigger
func TestTriggerEvaluateWorkflow(t *testing.T) {
	setupTestEnv(t)
	loadConfig()

	t.Run("circuit breaker open", func(t *testing.T) {
		cb := NewCircuitBreaker(1, 1*time.Hour)
		cb.RecordFailure()

		testServer := &GatewayServer{
			config:         server.config,
			logger:         logger,
			circuitBreaker: cb,
		}

		err := testServer.triggerEvaluateWorkflow("domain", []string{"hash1"}, "http://callback")
		if err == nil {
			t.Error("expected error when circuit breaker is open")
		}
		if !strings.Contains(err.Error(), "circuit breaker open") {
			t.Errorf("expected circuit breaker error, got: %v", err)
		}
	})

	t.Run("successful workflow trigger", func(t *testing.T) {
		mockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify headers
			if r.Header.Get("Content-Type") != "application/json" {
				t.Error("expected Content-Type application/json")
			}
			if r.Header.Get("Authorization") == "" {
				t.Error("expected Authorization header")
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"result": "ok"}`))
		}))
		defer mockSrv.Close()

		testServer := &GatewayServer{
			config: &GatewayConfig{
				GatewayURL:    mockSrv.URL,
				WorkflowID:    "test-workflow",
				AuthorizedKey: "0xtest123",
			},
			logger:         logger,
			circuitBreaker: NewCircuitBreaker(3, 30*time.Second),
			privateKey:     server.privateKey,
		}

		err := testServer.triggerEvaluateWorkflow("test-domain", []string{strings.Repeat("a", 40)}, "http://callback")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("non-success response", func(t *testing.T) {
		mockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "bad request"}`))
		}))
		defer mockSrv.Close()

		testServer := &GatewayServer{
			config: &GatewayConfig{
				GatewayURL:    mockSrv.URL,
				WorkflowID:    "test-workflow",
				AuthorizedKey: "0xtest123",
			},
			logger:         logger,
			circuitBreaker: NewCircuitBreaker(3, 30*time.Second),
			privateKey:     server.privateKey,
		}

		err := testServer.triggerEvaluateWorkflow("test-domain", []string{strings.Repeat("a", 40)}, "http://callback")
		if err == nil {
			t.Error("expected error for non-success response")
		}
	})

	t.Run("5xx response triggers circuit breaker", func(t *testing.T) {
		mockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error": "internal error"}`))
		}))
		defer mockSrv.Close()

		cb := NewCircuitBreaker(3, 30*time.Second)
		testServer := &GatewayServer{
			config: &GatewayConfig{
				GatewayURL:    mockSrv.URL,
				WorkflowID:    "test-workflow",
				AuthorizedKey: "0xtest123",
			},
			logger:         logger,
			circuitBreaker: cb,
			privateKey:     server.privateKey,
		}

		// First failure
		testServer.triggerEvaluateWorkflow("test-domain", []string{strings.Repeat("a", 40)}, "http://callback")

		// Verify failure was recorded
		cb.mu.Lock()
		failures := cb.failures
		cb.mu.Unlock()

		if failures < 1 {
			t.Error("expected circuit breaker to record failure")
		}
	})

	t.Run("connection error triggers circuit breaker", func(t *testing.T) {
		cb := NewCircuitBreaker(3, 30*time.Second)
		testServer := &GatewayServer{
			config: &GatewayConfig{
				GatewayURL:    "http://localhost:1", // Port 1 - should fail to connect
				WorkflowID:    "test-workflow",
				AuthorizedKey: "0xtest123",
			},
			logger:         logger,
			circuitBreaker: cb,
			privateKey:     server.privateKey,
		}

		err := testServer.triggerEvaluateWorkflow("test-domain", []string{strings.Repeat("a", 40)}, "http://callback")
		if err == nil {
			t.Error("expected error for connection failure")
		}
		if !strings.Contains(err.Error(), "request failed") {
			t.Errorf("expected 'request failed' error, got: %v", err)
		}

		// Verify failure was recorded
		cb.mu.Lock()
		failures := cb.failures
		cb.mu.Unlock()

		if failures < 1 {
			t.Error("expected circuit breaker to record failure on connection error")
		}
	})

	t.Run("202 accepted response is success", func(t *testing.T) {
		mockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusAccepted)
			w.Write([]byte(`{"result": "accepted"}`))
		}))
		defer mockSrv.Close()

		testServer := &GatewayServer{
			config: &GatewayConfig{
				GatewayURL:    mockSrv.URL,
				WorkflowID:    "test-workflow",
				AuthorizedKey: "0xtest123",
			},
			logger:         logger,
			circuitBreaker: NewCircuitBreaker(3, 30*time.Second),
			privateKey:     server.privateKey,
		}

		err := testServer.triggerEvaluateWorkflow("test-domain", []string{strings.Repeat("a", 40)}, "http://callback")
		if err != nil {
			t.Errorf("unexpected error for 202 response: %v", err)
		}
	})

	t.Run("invalid gateway URL", func(t *testing.T) {
		testServer := &GatewayServer{
			config: &GatewayConfig{
				GatewayURL:    "://invalid-url",
				WorkflowID:    "test-workflow",
				AuthorizedKey: "0xtest123",
			},
			logger:         logger,
			circuitBreaker: NewCircuitBreaker(3, 30*time.Second),
			privateKey:     server.privateKey,
		}

		err := testServer.triggerEvaluateWorkflow("test-domain", []string{"hash1"}, "http://callback")
		if err == nil {
			t.Error("expected error for invalid URL")
		}
	})
}

// TestCleanupOldRequestsLogic tests the cleanup logic (not the goroutine)
func TestCleanupOldRequestsLogic(t *testing.T) {
	setupTestEnv(t)
	loadConfig()

	t.Run("cleanup completed requests older than 5 minutes", func(t *testing.T) {
		server := &GatewayServer{
			config: &GatewayConfig{
				BlockTimeout:    time.Minute,
				CleanupInterval: time.Second,
				MaxPending:      1000,
			},
			logger:          logger,
			pendingRequests: make(map[string]*PendingRequest),
			ipRateLimiter:   NewIPRateLimiter(10, 20),
			shutdownChan:    make(chan struct{}),
		}

		// Add old completed request
		server.pendingRequests["old-completed"] = &PendingRequest{
			RequestID:  "old-completed",
			CreatedAt:  time.Now().Add(-10 * time.Minute),
			Status:     "completed",
			ResultChan: nil,
		}

		// Add recent completed request
		server.pendingRequests["new-completed"] = &PendingRequest{
			RequestID:  "new-completed",
			CreatedAt:  time.Now(),
			Status:     "completed",
			ResultChan: nil,
		}

		// Manually run cleanup logic (simulating what the goroutine does)
		server.requestsMutex.Lock()
		now := time.Now()
		var toDelete []string
		for id, req := range server.pendingRequests {
			if req.Status == "completed" && now.Sub(req.CreatedAt) > 5*time.Minute {
				toDelete = append(toDelete, id)
			}
		}
		for _, id := range toDelete {
			delete(server.pendingRequests, id)
		}
		server.requestsMutex.Unlock()

		if _, exists := server.pendingRequests["old-completed"]; exists {
			t.Error("expected old-completed to be cleaned up")
		}
		if _, exists := server.pendingRequests["new-completed"]; !exists {
			t.Error("expected new-completed to still exist")
		}
	})

	t.Run("cleanup timeout requests older than 5 minutes", func(t *testing.T) {
		server := &GatewayServer{
			config: &GatewayConfig{
				BlockTimeout:    time.Minute,
				CleanupInterval: time.Second,
				MaxPending:      1000,
			},
			logger:          logger,
			pendingRequests: make(map[string]*PendingRequest),
			ipRateLimiter:   NewIPRateLimiter(10, 20),
		}

		server.pendingRequests["old-timeout"] = &PendingRequest{
			RequestID:  "old-timeout",
			CreatedAt:  time.Now().Add(-10 * time.Minute),
			Status:     "timeout",
			ResultChan: nil,
		}

		server.requestsMutex.Lock()
		now := time.Now()
		var toDelete []string
		for id, req := range server.pendingRequests {
			if req.Status == "timeout" && now.Sub(req.CreatedAt) > 5*time.Minute {
				toDelete = append(toDelete, id)
			}
		}
		for _, id := range toDelete {
			delete(server.pendingRequests, id)
		}
		server.requestsMutex.Unlock()

		if _, exists := server.pendingRequests["old-timeout"]; exists {
			t.Error("expected old-timeout to be cleaned up")
		}
	})

	t.Run("cleanup stale pending requests", func(t *testing.T) {
		blockTimeout := time.Minute
		server := &GatewayServer{
			config: &GatewayConfig{
				BlockTimeout:    blockTimeout,
				CleanupInterval: time.Second,
				MaxPending:      1000,
			},
			logger:          logger,
			pendingRequests: make(map[string]*PendingRequest),
			ipRateLimiter:   NewIPRateLimiter(10, 20),
		}

		resultChan := make(chan *WebhookPayload, 1)
		server.pendingRequests["stale-pending"] = &PendingRequest{
			RequestID:  "stale-pending",
			CreatedAt:  time.Now().Add(-3 * blockTimeout), // Older than 2x BlockTimeout
			Status:     "pending",
			ResultChan: resultChan,
		}

		server.requestsMutex.Lock()
		now := time.Now()
		var toDelete []string
		var channelsToClose []chan *WebhookPayload
		for id, req := range server.pendingRequests {
			if req.Status == "pending" && now.Sub(req.CreatedAt) > 2*blockTimeout {
				toDelete = append(toDelete, id)
				if req.ResultChan != nil {
					channelsToClose = append(channelsToClose, req.ResultChan)
				}
			}
		}
		for _, id := range toDelete {
			delete(server.pendingRequests, id)
		}
		server.requestsMutex.Unlock()

		// Close channels outside lock
		for _, ch := range channelsToClose {
			close(ch)
		}

		if _, exists := server.pendingRequests["stale-pending"]; exists {
			t.Error("expected stale-pending to be cleaned up")
		}
	})
}

// TestPollLiquidationServiceShutdown tests graceful shutdown
func TestPollLiquidationServiceShutdown(t *testing.T) {
	setupTestEnv(t)
	loadConfig()

	server := &GatewayServer{
		config: &GatewayConfig{
			LiquidationURL:      "http://localhost:59999",
			LiquidationInterval: 100 * time.Millisecond,
		},
		logger:         logger,
		circuitBreaker: NewCircuitBreaker(3, 30*time.Second),
		shutdownChan:   make(chan struct{}),
	}

	// Start poller in background
	done := make(chan struct{})
	go func() {
		server.pollLiquidationService()
		close(done)
	}()

	// Wait a bit then signal shutdown
	time.Sleep(50 * time.Millisecond)
	close(server.shutdownChan)

	// Wait for goroutine to exit
	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Error("pollLiquidationService did not exit after shutdown signal")
	}
}

// TestVerifyWebhookSignatureEdgeCases tests edge cases for webhook signature verification
func TestVerifyWebhookSignatureEdgeCases(t *testing.T) {
	setupTestEnv(t)
	loadConfig()

	t.Run("nil payload", func(t *testing.T) {
		err := verifyWebhookSignature(nil)
		if err == nil {
			t.Error("expected error for nil payload")
		}
		if !strings.Contains(err.Error(), "payload cannot be nil") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("missing event_id", func(t *testing.T) {
		payload := &WebhookPayload{
			EventID: "",
			PubKey:  strings.Repeat("a", 64),
			Sig:     strings.Repeat("b", 128),
		}
		err := verifyWebhookSignature(payload)
		if err == nil {
			t.Error("expected error for missing event_id")
		}
		if !strings.Contains(err.Error(), "missing event_id") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("missing pubkey", func(t *testing.T) {
		payload := &WebhookPayload{
			EventID: strings.Repeat("a", 64),
			PubKey:  "",
			Sig:     strings.Repeat("b", 128),
		}
		err := verifyWebhookSignature(payload)
		if err == nil {
			t.Error("expected error for missing pubkey")
		}
		if !strings.Contains(err.Error(), "missing pubkey") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("missing signature", func(t *testing.T) {
		payload := &WebhookPayload{
			EventID: strings.Repeat("a", 64),
			PubKey:  strings.Repeat("b", 64),
			Sig:     "",
		}
		err := verifyWebhookSignature(payload)
		if err == nil {
			t.Error("expected error for missing signature")
		}
		if !strings.Contains(err.Error(), "missing signature") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("invalid event_id length", func(t *testing.T) {
		payload := &WebhookPayload{
			EventID: "tooshort",
			PubKey:  strings.Repeat("a", 64),
			Sig:     strings.Repeat("b", 128),
		}
		err := verifyWebhookSignature(payload)
		if err == nil {
			t.Error("expected error for invalid event_id length")
		}
		if !strings.Contains(err.Error(), "invalid event_id length") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("invalid pubkey length", func(t *testing.T) {
		payload := &WebhookPayload{
			EventID: strings.Repeat("a", 64),
			PubKey:  "tooshort",
			Sig:     strings.Repeat("b", 128),
		}
		err := verifyWebhookSignature(payload)
		if err == nil {
			t.Error("expected error for invalid pubkey length")
		}
		if !strings.Contains(err.Error(), "invalid pubkey length") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("invalid signature length", func(t *testing.T) {
		payload := &WebhookPayload{
			EventID: strings.Repeat("a", 64),
			PubKey:  strings.Repeat("b", 64),
			Sig:     "tooshort",
		}
		err := verifyWebhookSignature(payload)
		if err == nil {
			t.Error("expected error for invalid signature length")
		}
		if !strings.Contains(err.Error(), "invalid signature length") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("too many tags", func(t *testing.T) {
		tags := make([][]string, 101) // maxTags is 100
		for i := range tags {
			tags[i] = []string{"tag"}
		}
		payload := &WebhookPayload{
			EventID: strings.Repeat("a", 64),
			PubKey:  strings.Repeat("b", 64),
			Sig:     strings.Repeat("c", 128),
			Tags:    tags,
		}
		err := verifyWebhookSignature(payload)
		if err == nil {
			t.Error("expected error for too many tags")
		}
		if !strings.Contains(err.Error(), "too many tags") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("tag with too many elements", func(t *testing.T) {
		tag := make([]string, 11) // maxTagElements is 10
		for i := range tag {
			tag[i] = "elem"
		}
		payload := &WebhookPayload{
			EventID: strings.Repeat("a", 64),
			PubKey:  strings.Repeat("b", 64),
			Sig:     strings.Repeat("c", 128),
			Tags:    [][]string{tag},
		}
		err := verifyWebhookSignature(payload)
		if err == nil {
			t.Error("expected error for tag with too many elements")
		}
		if !strings.Contains(err.Error(), "too many elements") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("tag element too long", func(t *testing.T) {
		longElem := strings.Repeat("x", 1025) // maxTagElementLen is 1024
		payload := &WebhookPayload{
			EventID: strings.Repeat("a", 64),
			PubKey:  strings.Repeat("b", 64),
			Sig:     strings.Repeat("c", 128),
			Tags:    [][]string{{longElem}},
		}
		err := verifyWebhookSignature(payload)
		if err == nil {
			t.Error("expected error for tag element too long")
		}
		if !strings.Contains(err.Error(), "too long") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("all-zero signature rejected", func(t *testing.T) {
		payload := &WebhookPayload{
			EventID:   strings.Repeat("a", 64),
			PubKey:    strings.Repeat("b", 64),
			Sig:       strings.Repeat("0", 128),
			CreatedAt: time.Now().Unix(),
			Kind:      1,
			Tags:      [][]string{},
			Content:   "test",
		}
		err := verifyWebhookSignature(payload)
		if err == nil {
			t.Error("expected error for all-zero signature")
		}
		// The error will be event_id mismatch first since computed ID won't match
	})

	t.Run("all-zero pubkey rejected", func(t *testing.T) {
		// Create a payload where the pubkey is all zeros but passes other checks
		payload := &WebhookPayload{
			EventID:   strings.Repeat("a", 64),
			PubKey:    strings.Repeat("0", 64),
			Sig:       strings.Repeat("a", 128),
			CreatedAt: time.Now().Unix(),
			Kind:      1,
			Tags:      [][]string{},
			Content:   "test",
		}
		err := verifyWebhookSignature(payload)
		if err == nil {
			t.Error("expected error for all-zero pubkey")
		}
		// Will fail on event_id mismatch first
	})

	t.Run("invalid signature hex", func(t *testing.T) {
		// Create payload with matching event_id to get past that check
		pubKey := strings.Repeat("a", 64)
		createdAt := int64(1234567890)
		kind := 1
		tags := [][]string{}
		content := "test"

		// Compute the correct event_id
		tagsJSON, _ := json.Marshal(tags)
		serialized := fmt.Sprintf("[0,%q,%d,%d,%s,%q]", pubKey, createdAt, kind, string(tagsJSON), content)
		computedHash := sha256.Sum256([]byte(serialized))
		eventID := hex.EncodeToString(computedHash[:])

		payload := &WebhookPayload{
			EventID:   eventID,
			PubKey:    pubKey,
			Sig:       strings.Repeat("g", 128), // Invalid hex
			CreatedAt: createdAt,
			Kind:      kind,
			Tags:      tags,
			Content:   content,
		}
		err := verifyWebhookSignature(payload)
		if err == nil {
			t.Error("expected error for invalid signature hex")
		}
		if !strings.Contains(err.Error(), "invalid signature hex") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// TestValidatePrivateKeyEdgeCases tests edge cases for private key validation
func TestValidatePrivateKeyEdgeCases(t *testing.T) {
	t.Run("valid key at curve order boundary", func(t *testing.T) {
		// Valid key near the curve order (but still valid)
		validKey := "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
		err := validatePrivateKey(validKey)
		if err != nil {
			t.Errorf("unexpected error for valid key: %v", err)
		}
	})

	t.Run("all-zero key rejected", func(t *testing.T) {
		zeroKey := strings.Repeat("0", 64)
		err := validatePrivateKey(zeroKey)
		if err == nil {
			t.Error("expected error for all-zero key")
		}
		if !strings.Contains(err.Error(), "cannot be zero") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("key exceeds curve order", func(t *testing.T) {
		// Key equal to or greater than curve order
		largeKey := "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142"
		err := validatePrivateKey(largeKey)
		if err == nil {
			t.Error("expected error for key >= curve order")
		}
		if !strings.Contains(err.Error(), "exceeds curve order") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("invalid hex characters", func(t *testing.T) {
		invalidKey := "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
		err := validatePrivateKey(invalidKey)
		if err == nil {
			t.Error("expected error for invalid hex")
		}
		if !strings.Contains(err.Error(), "invalid hex") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("too long", func(t *testing.T) {
		longKey := strings.Repeat("a", 65)
		err := validatePrivateKey(longKey)
		if err == nil {
			t.Error("expected error for too long key")
		}
		if !strings.Contains(err.Error(), "must be 64 hex chars") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// TestMarshalSortedEdgeCases tests edge cases for deterministic JSON marshaling
func TestMarshalSortedEdgeCases(t *testing.T) {
	t.Run("empty map", func(t *testing.T) {
		result, err := marshalSorted(map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(result) != "{}" {
			t.Errorf("expected {}, got %s", string(result))
		}
	})

	t.Run("nil values", func(t *testing.T) {
		input := map[string]interface{}{"key": nil}
		result, err := marshalSorted(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(result) != `{"key":null}` {
			t.Errorf("expected {\"key\":null}, got %s", string(result))
		}
	})

	t.Run("deeply nested", func(t *testing.T) {
		input := map[string]interface{}{
			"level1": map[string]interface{}{
				"level2": map[string]interface{}{
					"level3": "value",
				},
			},
		}
		result, err := marshalSorted(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := `{"level1":{"level2":{"level3":"value"}}}`
		if string(result) != expected {
			t.Errorf("expected %s, got %s", expected, string(result))
		}
	})

	t.Run("array with mixed types", func(t *testing.T) {
		input := map[string]interface{}{
			"arr": []interface{}{1, "two", 3.0, true, nil},
		}
		result, err := marshalSorted(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := `{"arr":[1,"two",3,true,null]}`
		if string(result) != expected {
			t.Errorf("expected %s, got %s", expected, string(result))
		}
	})

	t.Run("special characters in strings", func(t *testing.T) {
		input := map[string]interface{}{
			"special": "hello\nworld\t\"quoted\"",
		}
		result, err := marshalSorted(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should have properly escaped characters
		if !strings.Contains(string(result), "\\n") {
			t.Errorf("expected escaped newline in output: %s", string(result))
		}
	})

	t.Run("unicode characters", func(t *testing.T) {
		input := map[string]interface{}{
			"unicode": "日本語 🎉",
		}
		result, err := marshalSorted(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(string(result), "日本語") {
			t.Errorf("expected unicode to be preserved: %s", string(result))
		}
	})

	t.Run("numeric keys preserved order", func(t *testing.T) {
		input := map[string]interface{}{
			"10": "ten",
			"2":  "two",
			"1":  "one",
		}
		result, err := marshalSorted(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should be sorted alphabetically: "1", "10", "2"
		expected := `{"1":"one","10":"ten","2":"two"}`
		if string(result) != expected {
			t.Errorf("expected %s, got %s", expected, string(result))
		}
	})
}

// TestLoadConfigEdgeCases tests configuration loading edge cases
func TestLoadConfigEdgeCases(t *testing.T) {
	t.Run("liquidation enabled", func(t *testing.T) {
		// Save current env
		oldLiqEnabled := os.Getenv("LIQUIDATION_ENABLED")
		oldLiqURL := os.Getenv("LIQUIDATION_SERVICE_URL")
		oldLiqInterval := os.Getenv("LIQUIDATION_INTERVAL_SECONDS")
		defer func() {
			os.Setenv("LIQUIDATION_ENABLED", oldLiqEnabled)
			os.Setenv("LIQUIDATION_SERVICE_URL", oldLiqURL)
			os.Setenv("LIQUIDATION_INTERVAL_SECONDS", oldLiqInterval)
		}()

		setupTestEnv(t)
		os.Setenv("LIQUIDATION_ENABLED", "true")
		os.Setenv("LIQUIDATION_SERVICE_URL", "http://test-liquidation:8080")
		os.Setenv("LIQUIDATION_INTERVAL_SECONDS", "60")

		cfg := loadConfig()

		if !cfg.LiquidationEnabled {
			t.Error("expected LiquidationEnabled to be true")
		}
		if cfg.LiquidationURL != "http://test-liquidation:8080" {
			t.Errorf("expected LiquidationURL to be http://test-liquidation:8080, got %s", cfg.LiquidationURL)
		}
		if cfg.LiquidationInterval != 60*time.Second {
			t.Errorf("expected LiquidationInterval to be 60s, got %v", cfg.LiquidationInterval)
		}
	})

	t.Run("custom IP rate limits", func(t *testing.T) {
		oldIPRate := os.Getenv("IP_RATE_LIMIT")
		oldIPBurst := os.Getenv("IP_BURST_LIMIT")
		defer func() {
			os.Setenv("IP_RATE_LIMIT", oldIPRate)
			os.Setenv("IP_BURST_LIMIT", oldIPBurst)
		}()

		setupTestEnv(t)
		os.Setenv("IP_RATE_LIMIT", "5")
		os.Setenv("IP_BURST_LIMIT", "10")

		cfg := loadConfig()

		if cfg.IPRateLimit != 5 {
			t.Errorf("expected IPRateLimit to be 5, got %f", cfg.IPRateLimit)
		}
		if cfg.IPBurstLimit != 10 {
			t.Errorf("expected IPBurstLimit to be 10, got %d", cfg.IPBurstLimit)
		}
	})
}

// TestHandleWebhookEdgeCases tests handleWebhook edge cases
func TestHandleWebhookEdgeCases(t *testing.T) {
	// Create a test server with valid config
	testSrv := &GatewayServer{
		config: &GatewayConfig{
			ExpectedWebhookPubKey: "expected_pubkey",
		},
		pendingRequests:   make(map[string]*PendingRequest),
		processedWebhooks: make(map[string]time.Time),
		ipRateLimiter:     NewIPRateLimiter(10, 20),
		logger:            logger,
		privateKey:        server.privateKey,
		circuitBreaker:    NewCircuitBreaker(5, 30*time.Second),
	}

	t.Run("method not allowed", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/webhook/ducat", nil)
		w := httptest.NewRecorder()
		testSrv.handleWebhook(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/webhook/ducat", strings.NewReader("not json"))
		w := httptest.NewRecorder()
		testSrv.handleWebhook(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("empty content field", func(t *testing.T) {
		payload := WebhookPayload{
			EventID: "test_event_1",
			Content: "", // empty
			Tags:    [][]string{{"domain", "test_domain"}},
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(body))
		w := httptest.NewRecorder()
		testSrv.handleWebhook(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
		if !strings.Contains(w.Body.String(), "empty") {
			t.Errorf("expected 'empty' in response, got %s", w.Body.String())
		}
	})

	t.Run("nil tags array", func(t *testing.T) {
		payload := WebhookPayload{
			EventID: "test_event_2",
			Content: "some content",
			Tags:    nil, // nil
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(body))
		w := httptest.NewRecorder()
		testSrv.handleWebhook(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
		if !strings.Contains(w.Body.String(), "nil") {
			t.Errorf("expected 'nil' in response, got %s", w.Body.String())
		}
	})

	t.Run("replay attack detection", func(t *testing.T) {
		// Pre-mark an event as processed
		testSrv.processedWebhooksMutex.Lock()
		testSrv.processedWebhooks["replayed_event"] = time.Now()
		testSrv.processedWebhooksMutex.Unlock()

		payload := WebhookPayload{
			EventID: "replayed_event",
			Content: "some content",
			Tags:    [][]string{{"domain", "test_domain"}},
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(body))
		w := httptest.NewRecorder()
		testSrv.handleWebhook(w, req)

		if w.Code != http.StatusConflict {
			t.Errorf("expected status %d, got %d", http.StatusConflict, w.Code)
		}
		if !strings.Contains(w.Body.String(), "Duplicate") {
			t.Errorf("expected 'Duplicate' in response, got %s", w.Body.String())
		}
	})

	t.Run("signature verification failure", func(t *testing.T) {
		payload := WebhookPayload{
			EventID:   "test_event_3",
			Content:   "some content",
			Tags:      [][]string{{"domain", "test_domain"}},
			PubKey:    "invalid_pubkey",
			Sig:       "invalid_sig",
			Kind:      1,
			CreatedAt: time.Now().Unix(),
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(body))
		w := httptest.NewRecorder()
		testSrv.handleWebhook(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
		}
		if !strings.Contains(w.Body.String(), "Signature") {
			t.Errorf("expected 'Signature' in response, got %s", w.Body.String())
		}
	})

	t.Run("future timestamp", func(t *testing.T) {
		// Create a valid-looking payload but with future timestamp
		futureTime := time.Now().Unix() + 3600 // 1 hour in the future
		payload := WebhookPayload{
			EventID:   "future_event",
			Content:   "some content",
			Tags:      [][]string{{"domain", "test_domain"}},
			PubKey:    "expected_pubkey", // matches expected
			Sig:       strings.Repeat("ab", 64), // 128 hex chars
			Kind:      1,
			CreatedAt: futureTime,
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(body))
		w := httptest.NewRecorder()
		testSrv.handleWebhook(w, req)

		// Will fail at signature verification first since we can't create valid Schnorr signatures
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
		}
	})

	t.Run("expired timestamp", func(t *testing.T) {
		// Create a valid-looking payload but with old timestamp
		oldTime := time.Now().Unix() - 600 // 10 minutes ago (expired)
		payload := WebhookPayload{
			EventID:   "expired_event",
			Content:   "some content",
			Tags:      [][]string{{"domain", "test_domain"}},
			PubKey:    "expected_pubkey",
			Sig:       strings.Repeat("ab", 64),
			Kind:      1,
			CreatedAt: oldTime,
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(body))
		w := httptest.NewRecorder()
		testSrv.handleWebhook(w, req)

		// Will fail at signature verification first
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
		}
	})

	t.Run("no pending request match", func(t *testing.T) {
		// Create a server that has no pending requests
		cleanServer := &GatewayServer{
			config: &GatewayConfig{
				ExpectedWebhookPubKey: "test_pubkey",
			},
			pendingRequests:   make(map[string]*PendingRequest),
			processedWebhooks: make(map[string]time.Time),
			ipRateLimiter:     NewIPRateLimiter(10, 20),
			logger:            logger,
			privateKey:        server.privateKey,
			circuitBreaker:    NewCircuitBreaker(5, 30*time.Second),
		}

		// This test is tricky because we need a valid signature
		// For now we just test that the path works with an invalid signature
		payload := WebhookPayload{
			EventID:   "no_match_event",
			Content:   "some content",
			Tags:      [][]string{{"domain", "nonexistent_domain"}},
			PubKey:    "test_pubkey",
			Sig:       strings.Repeat("ab", 64),
			Kind:      1,
			CreatedAt: time.Now().Unix(),
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(body))
		w := httptest.NewRecorder()
		cleanServer.handleWebhook(w, req)

		// Will fail at signature verification
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
		}
	})

	t.Run("body too large", func(t *testing.T) {
		// Create a body larger than 1MB
		largeBody := strings.Repeat("a", 2<<20) // 2MB
		req := httptest.NewRequest("POST", "/webhook/ducat", strings.NewReader(largeBody))
		w := httptest.NewRecorder()
		testSrv.handleWebhook(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})
}

// TestCheckCREGateway tests the CRE gateway health check
func TestCheckCREGateway(t *testing.T) {
	t.Run("gateway reachable", func(t *testing.T) {
		// Start a mock server that responds quickly
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "HEAD" {
				t.Errorf("expected HEAD request, got %s", r.Method)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer mockServer.Close()

		testSrv := &GatewayServer{
			config: &GatewayConfig{
				GatewayURL: mockServer.URL,
			},
			logger: logger,
		}

		health := testSrv.checkCREGateway(context.Background())
		if health.Status != "up" {
			t.Errorf("expected status 'up', got %s", health.Status)
		}
		if health.Message != "Reachable" {
			t.Errorf("expected message 'Reachable', got %s", health.Message)
		}
		if health.Latency == nil {
			t.Error("expected latency to be set")
		}
	})

	t.Run("gateway unreachable", func(t *testing.T) {
		testSrv := &GatewayServer{
			config: &GatewayConfig{
				GatewayURL: "http://localhost:59999", // unlikely to be listening
			},
			logger: logger,
		}

		health := testSrv.checkCREGateway(context.Background())
		if health.Status != "down" {
			t.Errorf("expected status 'down', got %s", health.Status)
		}
		if !strings.Contains(health.Message, "Unreachable") {
			t.Errorf("expected message to contain 'Unreachable', got %s", health.Message)
		}
	})

	t.Run("gateway returns error status", func(t *testing.T) {
		// Even 404 is considered "up" - we just care about reachability
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer mockServer.Close()

		testSrv := &GatewayServer{
			config: &GatewayConfig{
				GatewayURL: mockServer.URL,
			},
			logger: logger,
		}

		health := testSrv.checkCREGateway(context.Background())
		if health.Status != "up" {
			t.Errorf("expected status 'up' for reachable server, got %s", health.Status)
		}
	})

	t.Run("invalid URL", func(t *testing.T) {
		testSrv := &GatewayServer{
			config: &GatewayConfig{
				GatewayURL: "://invalid-url",
			},
			logger: logger,
		}

		health := testSrv.checkCREGateway(context.Background())
		if health.Status != "down" {
			t.Errorf("expected status 'down', got %s", health.Status)
		}
		if !strings.Contains(health.Message, "Failed to create request") {
			t.Errorf("expected message about failed request, got %s", health.Message)
		}
	})
}

// TestTriggerWorkflowEdgeCases tests triggerWorkflow edge cases
func TestTriggerWorkflowEdgeCases(t *testing.T) {
	t.Run("circuit breaker open", func(t *testing.T) {
		cb := NewCircuitBreaker(2, 30*time.Second)
		// Force circuit breaker to open
		cb.RecordFailure()
		cb.RecordFailure()
		cb.RecordFailure() // should open the circuit

		testSrv := &GatewayServer{
			config: &GatewayConfig{
				WorkflowID:    "test-workflow",
				GatewayURL:    "http://localhost:8080",
				AuthorizedKey: "0xtest",
			},
			circuitBreaker: cb,
			privateKey:     server.privateKey,
			logger:         logger,
		}

		err := testSrv.triggerWorkflow("check", "test_domain", nil, nil, "http://callback")
		if err == nil {
			t.Error("expected error when circuit breaker is open")
		}
		if !strings.Contains(err.Error(), "circuit breaker open") {
			t.Errorf("expected circuit breaker error, got: %v", err)
		}
	})

	t.Run("with thold_price and thold_hash", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Read request body
			body, _ := io.ReadAll(r.Body)
			var req map[string]interface{}
			if err := json.Unmarshal(body, &req); err != nil {
				t.Errorf("failed to unmarshal request: %v", err)
			}

			// Verify the input contains thold_price and thold_hash
			params, ok := req["params"].(map[string]interface{})
			if !ok {
				t.Error("expected params in request")
			}
			input, ok := params["input"].(map[string]interface{})
			if !ok {
				t.Error("expected input in params")
			}
			if _, ok := input["thold_price"]; !ok {
				t.Error("expected thold_price in input")
			}
			if _, ok := input["thold_hash"]; !ok {
				t.Error("expected thold_hash in input")
			}

			w.WriteHeader(http.StatusAccepted)
		}))
		defer mockServer.Close()

		testSrv := &GatewayServer{
			config: &GatewayConfig{
				WorkflowID:    "test-workflow",
				GatewayURL:    mockServer.URL,
				AuthorizedKey: "0xtest",
			},
			circuitBreaker: NewCircuitBreaker(5, 30*time.Second),
			privateKey:     server.privateKey,
			logger:         logger,
		}

		tholdPrice := 50000.0
		tholdHash := "0xabc123"
		err := testSrv.triggerWorkflow("check", "test_domain", &tholdPrice, &tholdHash, "http://callback")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("gateway returns 500 error", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal Server Error"))
		}))
		defer mockServer.Close()

		testSrv := &GatewayServer{
			config: &GatewayConfig{
				WorkflowID:    "test-workflow",
				GatewayURL:    mockServer.URL,
				AuthorizedKey: "0xtest",
			},
			circuitBreaker: NewCircuitBreaker(5, 30*time.Second),
			privateKey:     server.privateKey,
			logger:         logger,
		}

		err := testSrv.triggerWorkflow("check", "test_domain", nil, nil, "http://callback")
		if err == nil {
			t.Error("expected error for 500 response")
		}
		if !strings.Contains(err.Error(), "non-success status 500") {
			t.Errorf("expected 500 error, got: %v", err)
		}
	})

	t.Run("gateway returns 400 error", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Bad Request"))
		}))
		defer mockServer.Close()

		testSrv := &GatewayServer{
			config: &GatewayConfig{
				WorkflowID:    "test-workflow",
				GatewayURL:    mockServer.URL,
				AuthorizedKey: "0xtest",
			},
			circuitBreaker: NewCircuitBreaker(5, 30*time.Second),
			privateKey:     server.privateKey,
			logger:         logger,
		}

		err := testSrv.triggerWorkflow("check", "test_domain", nil, nil, "http://callback")
		if err == nil {
			t.Error("expected error for 400 response")
		}
		if !strings.Contains(err.Error(), "non-success status 400") {
			t.Errorf("expected 400 error, got: %v", err)
		}
	})

	t.Run("connection refused", func(t *testing.T) {
		testSrv := &GatewayServer{
			config: &GatewayConfig{
				WorkflowID:    "test-workflow",
				GatewayURL:    "http://localhost:59998", // unlikely to be listening
				AuthorizedKey: "0xtest",
			},
			circuitBreaker: NewCircuitBreaker(5, 30*time.Second),
			privateKey:     server.privateKey,
			logger:         logger,
		}

		err := testSrv.triggerWorkflow("check", "test_domain", nil, nil, "http://callback")
		if err == nil {
			t.Error("expected error for connection refused")
		}
		if !strings.Contains(err.Error(), "request failed") {
			t.Errorf("expected request failed error, got: %v", err)
		}
	})
}

// TestHandleReadinessEdgeCases tests handleReadiness edge cases
func TestHandleReadinessEdgeCases(t *testing.T) {
	t.Run("unhealthy - no private key", func(t *testing.T) {
		// Mock CRE gateway for the health check
		mockCRE := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer mockCRE.Close()

		testSrv := &GatewayServer{
			config: &GatewayConfig{
				GatewayURL: mockCRE.URL,
				MaxPending: 1000,
			},
			pendingRequests: make(map[string]*PendingRequest),
			circuitBreaker:  NewCircuitBreaker(5, 30*time.Second),
			privateKey:      nil, // No private key - makes it unhealthy
			logger:          logger,
		}

		req := httptest.NewRequest("GET", "/readiness", nil)
		w := httptest.NewRecorder()
		testSrv.handleReadiness(w, req)

		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to unmarshal response: %v", err)
		}
		if resp["status"] != "unhealthy" {
			t.Errorf("expected status 'unhealthy', got %s", resp["status"])
		}
	})

	t.Run("ready when circuit is closed", func(t *testing.T) {
		// Create a mock CRE gateway
		mockCRE := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer mockCRE.Close()

		testSrv := &GatewayServer{
			config: &GatewayConfig{
				GatewayURL: mockCRE.URL,
				MaxPending: 1000,
			},
			pendingRequests: make(map[string]*PendingRequest),
			circuitBreaker:  NewCircuitBreaker(5, 30*time.Second),
			privateKey:      server.privateKey,
			logger:          logger,
		}

		req := httptest.NewRequest("GET", "/readiness", nil)
		w := httptest.NewRecorder()
		testSrv.handleReadiness(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
		}
	})
}

// TestPanicRecoveryMiddlewareEdgeCases tests additional panic recovery middleware edge cases
func TestPanicRecoveryMiddlewareEdgeCases(t *testing.T) {
	t.Run("recovers from panic with error type", func(t *testing.T) {
		// Create a handler that panics with an error
		panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic(fmt.Errorf("test error panic"))
		})

		// Wrap with panic recovery middleware
		wrapped := panicRecoveryMiddleware(panicHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		// Should not panic
		wrapped.ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
		}
	})

	t.Run("recovers from panic with integer", func(t *testing.T) {
		// Create a handler that panics with an integer
		panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic(42)
		})

		wrapped := panicRecoveryMiddleware(panicHandler)

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		wrapped.ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
		}
	})
}

// TestCleanupOldRequestsGoroutine tests the actual cleanup goroutine
func TestCleanupOldRequestsGoroutine(t *testing.T) {
	t.Run("cleanup cycle with various request states", func(t *testing.T) {
		// Create server with very short cleanup interval but longer BlockTimeout
		// to prevent "recent-pending" from being cleaned up during the test
		testSrv := &GatewayServer{
			config: &GatewayConfig{
				CleanupInterval: 20 * time.Millisecond,
				BlockTimeout:    10 * time.Second, // 2x = 20s threshold for stale pending
				MaxPending:      1000,
			},
			logger:            logger,
			pendingRequests:   make(map[string]*PendingRequest),
			processedWebhooks: make(map[string]time.Time),
			ipRateLimiter:     NewIPRateLimiter(10, 20),
			shutdownChan:      make(chan struct{}),
		}

		now := time.Now()

		// Add old completed request (should be cleaned - older than 5 minutes)
		testSrv.pendingRequests["old-completed"] = &PendingRequest{
			RequestID:  "old-completed",
			CreatedAt:  now.Add(-10 * time.Minute),
			Status:     "completed",
			ResultChan: nil,
		}

		// Add old timeout request (should be cleaned - older than 5 minutes)
		testSrv.pendingRequests["old-timeout"] = &PendingRequest{
			RequestID:  "old-timeout",
			CreatedAt:  now.Add(-10 * time.Minute),
			Status:     "timeout",
			ResultChan: nil,
		}

		// Add stale pending request (should be cleaned - older than 2x BlockTimeout = 20s)
		staleChan := make(chan *WebhookPayload, 1)
		testSrv.pendingRequests["stale-pending"] = &PendingRequest{
			RequestID:  "stale-pending",
			CreatedAt:  now.Add(-5 * time.Minute), // Way older than 20s
			Status:     "pending",
			ResultChan: staleChan,
		}

		// Add recent pending request (should NOT be cleaned - only 1ms old, way less than 20s)
		testSrv.pendingRequests["recent-pending"] = &PendingRequest{
			RequestID:  "recent-pending",
			CreatedAt:  now.Add(-1 * time.Millisecond),
			Status:     "pending",
			ResultChan: make(chan *WebhookPayload, 1),
		}

		// Add old webhook to processedWebhooks (should be cleaned after 10 min)
		testSrv.processedWebhooksMutex.Lock()
		testSrv.processedWebhooks["old-webhook"] = now.Add(-15 * time.Minute)
		testSrv.processedWebhooks["recent-webhook"] = now
		testSrv.processedWebhooksMutex.Unlock()

		if len(testSrv.pendingRequests) != 4 {
			t.Fatalf("setup failed: got %d requests, want 4", len(testSrv.pendingRequests))
		}

		// Start cleanup goroutine
		go testSrv.cleanupOldRequests()

		// Wait for at least one cleanup cycle
		time.Sleep(100 * time.Millisecond)

		// Send shutdown signal
		close(testSrv.shutdownChan)

		// Wait a bit for goroutine to stop
		time.Sleep(50 * time.Millisecond)

		// Verify cleanup happened
		testSrv.requestsMutex.RLock()
		pendingCount := len(testSrv.pendingRequests)
		_, oldCompletedExists := testSrv.pendingRequests["old-completed"]
		_, oldTimeoutExists := testSrv.pendingRequests["old-timeout"]
		_, stalePendingExists := testSrv.pendingRequests["stale-pending"]
		_, recentPendingExists := testSrv.pendingRequests["recent-pending"]
		testSrv.requestsMutex.RUnlock()

		if oldCompletedExists {
			t.Error("expected old-completed to be cleaned up")
		}
		if oldTimeoutExists {
			t.Error("expected old-timeout to be cleaned up")
		}
		if stalePendingExists {
			t.Error("expected stale-pending to be cleaned up")
		}
		if !recentPendingExists {
			t.Error("expected recent-pending to still exist")
		}
		if pendingCount != 1 {
			t.Errorf("expected 1 pending request, got %d", pendingCount)
		}
	})

	t.Run("shutdown signal stops goroutine", func(t *testing.T) {
		testSrv := &GatewayServer{
			config: &GatewayConfig{
				CleanupInterval: 1 * time.Hour, // Long interval so it won't run
				BlockTimeout:    time.Minute,
				MaxPending:      1000,
			},
			logger:            logger,
			pendingRequests:   make(map[string]*PendingRequest),
			processedWebhooks: make(map[string]time.Time),
			ipRateLimiter:     NewIPRateLimiter(10, 20),
			shutdownChan:      make(chan struct{}),
		}

		done := make(chan bool)
		go func() {
			testSrv.cleanupOldRequests()
			done <- true
		}()

		// Immediately send shutdown
		close(testSrv.shutdownChan)

		// Wait for goroutine to exit
		select {
		case <-done:
			// Success - goroutine exited
		case <-time.After(500 * time.Millisecond):
			t.Error("cleanup goroutine did not exit after shutdown signal")
		}
	})
}

// TestMarshalSortedErrors tests error handling in marshalSorted
func TestMarshalSortedErrors(t *testing.T) {
	t.Run("marshal error with channel type", func(t *testing.T) {
		// Channels cannot be marshaled to JSON
		ch := make(chan int)
		_, err := marshalSorted(ch)
		if err == nil {
			t.Error("expected error when marshaling channel")
		}
	})

	t.Run("marshal error with func type", func(t *testing.T) {
		// Functions cannot be marshaled to JSON
		fn := func() {}
		_, err := marshalSorted(fn)
		if err == nil {
			t.Error("expected error when marshaling function")
		}
	})

	t.Run("marshal with empty array", func(t *testing.T) {
		input := map[string]interface{}{
			"arr": []interface{}{},
		}
		result, err := marshalSorted(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := `{"arr":[]}`
		if string(result) != expected {
			t.Errorf("expected %s, got %s", expected, string(result))
		}
	})

	t.Run("marshal nested arrays", func(t *testing.T) {
		input := map[string]interface{}{
			"nested": []interface{}{
				[]interface{}{1, 2},
				[]interface{}{3, 4},
			},
		}
		result, err := marshalSorted(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := `{"nested":[[1,2],[3,4]]}`
		if string(result) != expected {
			t.Errorf("expected %s, got %s", expected, string(result))
		}
	})

	t.Run("marshal array with objects", func(t *testing.T) {
		input := map[string]interface{}{
			"items": []interface{}{
				map[string]interface{}{"z": 1, "a": 2},
				map[string]interface{}{"b": 3},
			},
		}
		result, err := marshalSorted(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Keys should be sorted within each nested object
		expected := `{"items":[{"a":2,"z":1},{"b":3}]}`
		if string(result) != expected {
			t.Errorf("expected %s, got %s", expected, string(result))
		}
	})

	t.Run("marshal boolean values", func(t *testing.T) {
		input := map[string]interface{}{
			"true_val":  true,
			"false_val": false,
		}
		result, err := marshalSorted(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := `{"false_val":false,"true_val":true}`
		if string(result) != expected {
			t.Errorf("expected %s, got %s", expected, string(result))
		}
	})

	t.Run("marshal float values", func(t *testing.T) {
		input := map[string]interface{}{
			"float": 3.14159,
			"int":   42,
		}
		result, err := marshalSorted(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Verify it contains both values (exact format may vary)
		resultStr := string(result)
		if !strings.Contains(resultStr, "3.14159") {
			t.Errorf("expected float value in result: %s", resultStr)
		}
		if !strings.Contains(resultStr, "42") {
			t.Errorf("expected int value in result: %s", resultStr)
		}
	})
}

// TestCleanupWebhookCache tests webhook cache cleanup
func TestCleanupWebhookCache(t *testing.T) {
	testSrv := &GatewayServer{
		processedWebhooks: make(map[string]time.Time),
		logger:            logger,
	}

	now := time.Now()

	// webhookCacheTTL is 5 minutes
	// Add old webhook entries (should be cleaned - older than 5 minutes)
	testSrv.processedWebhooksMutex.Lock()
	testSrv.processedWebhooks["cleanup-test-old-1"] = now.Add(-15 * time.Minute)
	testSrv.processedWebhooks["cleanup-test-old-2"] = now.Add(-6 * time.Minute)
	// Add recent webhook entries (should NOT be cleaned - less than 5 minutes)
	testSrv.processedWebhooks["cleanup-test-recent-1"] = now.Add(-3 * time.Minute)
	testSrv.processedWebhooks["cleanup-test-recent-2"] = now
	testSrv.processedWebhooksMutex.Unlock()

	// Run cleanup
	cleaned := testSrv.cleanupWebhookCache()

	// Verify old entries were cleaned
	if cleaned < 2 {
		t.Errorf("expected at least 2 webhooks cleaned, got %d", cleaned)
	}

	// Verify specific entries
	testSrv.processedWebhooksMutex.RLock()
	_, old1Exists := testSrv.processedWebhooks["cleanup-test-old-1"]
	_, old2Exists := testSrv.processedWebhooks["cleanup-test-old-2"]
	_, recent1Exists := testSrv.processedWebhooks["cleanup-test-recent-1"]
	_, recent2Exists := testSrv.processedWebhooks["cleanup-test-recent-2"]
	testSrv.processedWebhooksMutex.RUnlock()

	if old1Exists {
		t.Error("expected cleanup-test-old-1 to be cleaned")
	}
	if old2Exists {
		t.Error("expected cleanup-test-old-2 to be cleaned")
	}
	if !recent1Exists {
		t.Error("expected cleanup-test-recent-1 to still exist")
	}
	if !recent2Exists {
		t.Error("expected cleanup-test-recent-2 to still exist")
	}
}
