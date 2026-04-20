package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
)

// NostrEvent represents a Nostr event from the relay
type NostrEvent struct {
	ID        string     `json:"id"`
	PubKey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

type batchFetchRequest struct {
	DTags []string `json:"d_tags"`
}

type batchFetchResult struct {
	DTag  string          `json:"d_tag"`
	Event json.RawMessage `json:"event,omitempty"`
	Error string          `json:"error,omitempty"`
}

type batchFetchResponse struct {
	Success bool               `json:"success"`
	Results []batchFetchResult `json:"results"`
	Message string             `json:"message"`
}

// NostrClient handles fetching quotes from Nostr relays
type NostrClient struct {
	relayURL     string
	oraclePubkey string
	httpClient   *http.Client
	logger       *zap.Logger
}

// NewNostrClient creates a new Nostr client
func NewNostrClient(relayURL, oraclePubkey string, logger *zap.Logger) *NostrClient {
	return &NostrClient{
		relayURL:     relayURL,
		oraclePubkey: oraclePubkey,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		logger: logger,
	}
}

// FetchQuoteByDTag fetches a quote from the Nostr relay by d-tag (commit_hash)
// Uses the strfry-http /api/quotes endpoint with d query parameter
func (c *NostrClient) FetchQuoteByDTag(dtag string) (*PriceContractResponse, error) {
	// Query relay using NIP-01 filter with #h tag (matches client-sdk)
	reqURL := fmt.Sprintf("%s/api/query", c.relayURL)

	c.logger.Debug("Fetching quote from Nostr by h-tag",
		zap.String("url", reqURL),
		zap.String("dtag", dtag),
	)

	filter := map[string]interface{}{
		"kinds": []int{30000},
		"#h":    []string{dtag},
		"limit": 1,
	}
	reqBody, err := json.Marshal(filter)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query filter: %w", err)
	}

	req, err := http.NewRequest("POST", reqURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from relay: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("relay returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Try to parse as a single event first
	var event NostrEvent
	if err := json.Unmarshal(body, &event); err != nil {
		// Try to parse as an array of events (some relays return arrays)
		var events []NostrEvent
		if err := json.Unmarshal(body, &events); err != nil {
			return nil, fmt.Errorf("failed to parse response: %w", err)
		}
		if len(events) == 0 {
			return nil, nil // No events found
		}
		event = events[0]
	}

	// Parse the content as PriceContractResponse
	var quote PriceContractResponse
	if err := json.Unmarshal([]byte(event.Content), &quote); err != nil {
		return nil, fmt.Errorf("failed to parse quote content: %w", err)
	}

	c.logger.Debug("Quote fetched from Nostr",
		zap.String("dtag", dtag),
		zap.String("commit_hash", quote.CommitHash),
	)

	return &quote, nil
}

func (c *NostrClient) queryRecentThresholdEvents(limit int, until *int64) ([]NostrEvent, error) {
	reqURL := fmt.Sprintf("%s/api/query", c.relayURL)

	filter := map[string]interface{}{
		"kinds": []int{30000},
		"limit": limit,
	}
	if c.oraclePubkey != "" {
		filter["authors"] = []string{c.oraclePubkey}
	}
	if until != nil {
		filter["until"] = *until
	}

	reqBody, err := json.Marshal(filter)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal relay query filter: %w", err)
	}

	// Retry once on transient HTTP/2 stream errors (common with Cloudflare).
	const maxAttempts = 2
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		req, err := http.NewRequest("POST", reqURL, bytes.NewReader(reqBody))
		if err != nil {
			return nil, fmt.Errorf("failed to create relay query request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("failed to fetch from relay: %w", err)
			continue
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("failed to read relay response: %w", err)
			continue
		}

		if resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusServiceUnavailable {
			lastErr = fmt.Errorf("relay returned status %d: %s", resp.StatusCode, string(respBody))
			continue
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("relay returned status %d: %s", resp.StatusCode, string(respBody))
		}

		var events []NostrEvent
		if err := json.Unmarshal(respBody, &events); err != nil {
			var single NostrEvent
			if errSingle := json.Unmarshal(respBody, &single); errSingle != nil {
				return nil, fmt.Errorf("failed to parse relay query response: %w", err)
			}
			events = []NostrEvent{single}
		}

		return events, nil
	}

	return nil, lastErr
}

// FetchQuoteByTholdHash scans recent relay events and returns the newest quote
// whose content matches the provided thold_hash.
//
// Relay events are indexed by commit_hash (d-tag), not thold_hash, so this uses
// /api/query and matches against event content.
func (c *NostrClient) FetchQuoteByTholdHash(tholdHash string) (*PriceContractResponse, error) {
	normalizedHash := strings.ToLower(strings.TrimSpace(tholdHash))
	if len(normalizedHash) != 40 {
		return nil, fmt.Errorf("invalid thold_hash length: expected 40, got %d", len(normalizedHash))
	}

	const (
		pageLimit = 100
		maxPages  = 10
	)

	var until *int64

	for page := 0; page < maxPages; page++ {
		events, err := c.queryRecentThresholdEvents(pageLimit, until)
		if err != nil {
			return nil, err
		}

		if len(events) == 0 {
			return nil, nil
		}

		// Process newest events first to return the freshest quote for this thold_hash.
		sort.Slice(events, func(i, j int) bool {
			return events[i].CreatedAt > events[j].CreatedAt
		})

		minCreatedAt := events[len(events)-1].CreatedAt
		for _, event := range events {
			if event.CreatedAt < minCreatedAt {
				minCreatedAt = event.CreatedAt
			}

			if !strings.Contains(strings.ToLower(event.Content), normalizedHash) {
				continue
			}

			var quote PriceContractResponse
			if err := json.Unmarshal([]byte(event.Content), &quote); err != nil {
				continue
			}
			if strings.EqualFold(quote.TholdHash, normalizedHash) {
				return &quote, nil
			}
		}

		if len(events) < pageLimit || minCreatedAt <= 0 {
			break
		}

		nextUntil := minCreatedAt - 1
		if until != nil && nextUntil >= *until {
			break
		}
		until = &nextUntil
	}

	return nil, nil
}

// ResolveCommitHashesByTholdHashes resolves thold_hash values to relay d-tag commit hashes.
// It scans recent relay events in pages and returns any commit hashes it can find.
func (c *NostrClient) ResolveCommitHashesByTholdHashes(tholdHashes []string) (map[string]string, error) {
	targets := make(map[string]struct{}, len(tholdHashes))
	for _, raw := range tholdHashes {
		normalized := strings.ToLower(strings.TrimSpace(raw))
		if len(normalized) != 40 {
			continue
		}
		targets[normalized] = struct{}{}
	}

	resolved := make(map[string]string, len(targets))
	if len(targets) == 0 {
		return resolved, nil
	}

	const (
		// Keep page size small to avoid Cloudflare HTTP/2 stream errors.
		// limit=100 reliably passes through CF; limit>=200 triggers stream resets.
		pageLimit = 100
		maxPages  = 10
	)

	var until *int64
	for page := 0; page < maxPages && len(resolved) < len(targets); page++ {
		events, err := c.queryRecentThresholdEvents(pageLimit, until)
		if err != nil {
			return resolved, err
		}

		if len(events) == 0 {
			break
		}

		minCreatedAt := events[len(events)-1].CreatedAt
		for _, event := range events {
			if event.CreatedAt < minCreatedAt {
				minCreatedAt = event.CreatedAt
			}

			var quote PriceContractResponse
			if err := json.Unmarshal([]byte(event.Content), &quote); err != nil {
				continue
			}

			tholdHash := strings.ToLower(strings.TrimSpace(quote.TholdHash))
			if _, wanted := targets[tholdHash]; !wanted {
				continue
			}

			commitHash := strings.ToLower(strings.TrimSpace(quote.CommitHash))
			if !isValidHex(commitHash, 64) {
				continue
			}

			if _, already := resolved[tholdHash]; !already {
				resolved[tholdHash] = commitHash
			}
		}

		if len(events) < pageLimit || minCreatedAt <= 0 {
			break
		}

		nextUntil := minCreatedAt - 1
		if until != nil && nextUntil >= *until {
			break
		}
		until = &nextUntil
	}

	return resolved, nil
}

// QuoteExistsByDTag checks whether at least one quote exists in the relay for a d-tag.
// It returns (false, nil) for 404/not found and (true, nil) for 200/OK.
func (c *NostrClient) QuoteExistsByDTag(dtag string) (bool, error) {
	reqURL := fmt.Sprintf("%s/api/query", c.relayURL)

	filter := map[string]interface{}{
		"kinds": []int{30000},
		"#h":    []string{dtag},
		"limit": 1,
	}
	reqBody, err := json.Marshal(filter)
	if err != nil {
		return false, fmt.Errorf("failed to marshal query filter: %w", err)
	}

	req, err := http.NewRequest("POST", reqURL, bytes.NewReader(reqBody))
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to fetch from relay: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("relay returned status %d: %s", resp.StatusCode, string(body))
	}

	var events []interface{}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &events); err != nil {
		return false, nil
	}
	return len(events) > 0, nil
}

// QuoteExistsByDTagBatch checks quote existence for a batch of d-tags using the relay batch endpoint.
// It returns:
// - existsByTag: true when event is present, false when not found
// - perTagErrors: non-not-found relay errors keyed by d-tag
// - error: request/transport level error
func (c *NostrClient) QuoteExistsByDTagBatch(dtags []string) (map[string]bool, map[string]error, error) {
	existsByTag := make(map[string]bool, len(dtags))
	perTagErrors := make(map[string]error)
	if len(dtags) == 0 {
		return existsByTag, perTagErrors, nil
	}

	reqURL := fmt.Sprintf("%s/api/quotes/batch/fetch", c.relayURL)
	reqBody, err := json.Marshal(batchFetchRequest{DTags: dtags})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal batch request: %w", err)
	}

	req, err := http.NewRequest("POST", reqURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch from relay: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("relay returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var decoded batchFetchResponse
	if err := json.Unmarshal(respBody, &decoded); err != nil {
		return nil, nil, fmt.Errorf("failed to parse batch response: %w", err)
	}
	if !decoded.Success {
		return nil, nil, fmt.Errorf("relay batch fetch failed: %s", decoded.Message)
	}

	for _, dtag := range dtags {
		existsByTag[dtag] = false
	}

	for _, item := range decoded.Results {
		if item.DTag == "" {
			continue
		}
		if item.Error != "" {
			if strings.Contains(strings.ToLower(item.Error), "not found") {
				existsByTag[item.DTag] = false
				continue
			}
			perTagErrors[item.DTag] = errors.New(item.Error)
			continue
		}

		existsByTag[item.DTag] = len(item.Event) > 0 && string(item.Event) != "null"
	}

	return existsByTag, perTagErrors, nil
}

// CalculateCommitHash computes the BIP-340 tagged hash for a quote
// commit_hash = hash340("ducat/price_contract_commit", oracle_pubkey || chain_network || base_price || base_stamp || thold_price)
// IMPORTANT: Tag must match cre-hmac/crypto/crypto.go TagPriceCommitHash
func CalculateCommitHash(oraclePubkey, chainNetwork string, basePrice, baseStamp, tholdPrice uint32) (string, error) {
	// BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)
	tag := "ducat/price_contract_commit"
	tagHash := sha256.Sum256([]byte(tag))

	// Decode oracle pubkey from hex
	pubkeyBytes, err := hex.DecodeString(oraclePubkey)
	if err != nil {
		return "", fmt.Errorf("invalid oracle pubkey hex: %w", err)
	}
	if len(pubkeyBytes) != 32 {
		return "", fmt.Errorf("oracle pubkey must be 32 bytes, got %d", len(pubkeyBytes))
	}

	// Build message: pubkey || network || base_price || base_stamp || thold_price
	networkBytes := []byte(chainNetwork)
	basePriceBytes := make([]byte, 4)
	baseStampBytes := make([]byte, 4)
	tholdPriceBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(basePriceBytes, basePrice)
	binary.BigEndian.PutUint32(baseStampBytes, baseStamp)
	binary.BigEndian.PutUint32(tholdPriceBytes, tholdPrice)

	// Concatenate all components
	msg := make([]byte, 0, len(pubkeyBytes)+len(networkBytes)+12)
	msg = append(msg, pubkeyBytes...)
	msg = append(msg, networkBytes...)
	msg = append(msg, basePriceBytes...)
	msg = append(msg, baseStampBytes...)
	msg = append(msg, tholdPriceBytes...)

	// Compute tagged hash: SHA256(tagHash || tagHash || msg)
	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	h.Write(msg)
	result := h.Sum(nil)

	return hex.EncodeToString(result), nil
}

// PublishEvent forwards a signed Nostr event to the relay via POST /api/quotes.
// Used as redundancy: when CRE sends a batch_generated webhook, the gateway
// republishes the event to ensure it reaches the relay even if CRE's direct
// relay publish failed.
func (c *NostrClient) PublishEvent(event *NostrEvent) error {
	if event == nil || event.ID == "" || event.Sig == "" {
		return fmt.Errorf("invalid event: missing ID or signature")
	}

	reqURL := c.relayURL + "/api/quotes"

	eventJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	req, err := http.NewRequest("POST", reqURL, bytes.NewReader(eventJSON))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to publish to relay: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("relay returned status %d: %s", resp.StatusCode, string(body))
	}

	c.logger.Info("Published event to relay",
		zap.String("event_id", event.ID[:16]),
	)
	return nil
}

// CalculateCollateralRatio computes the collateral ratio as a percentage
// ratio = (thold_price / base_price) * 100
func CalculateCollateralRatio(basePrice, tholdPrice uint32) float64 {
	if basePrice == 0 {
		return 0
	}
	return float64(tholdPrice) / float64(basePrice) * 100.0
}

// QuoteExistsByHTag checks whether at least one event exists for an #h tag value.
func (c *NostrClient) QuoteExistsByHTag(htag string) (bool, error) {
	reqURL := fmt.Sprintf("%s/api/query", c.relayURL)

	filter := map[string]interface{}{
		"kinds": []int{30000},
		"#h":    []string{htag},
		"limit": 1,
	}

	reqJSON, err := json.Marshal(filter)
	if err != nil {
		return false, err
	}

	req, err := http.NewRequest("POST", reqURL, bytes.NewReader(reqJSON))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	return len(body) > 2, nil
}
