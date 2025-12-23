package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
			Timeout: 10 * time.Second,
		},
		logger: logger,
	}
}

// FetchQuoteByDTag fetches a quote from the Nostr relay by d-tag (commit_hash)
// Uses NIP-33 addressable events (kind:30078)
func (c *NostrClient) FetchQuoteByDTag(dtag string) (*PriceContractResponse, error) {
	// Build filter for NIP-33 addressable event query
	// Format: /nostr/addressable?pubkey=X&kind=30078&d=Y
	reqURL := fmt.Sprintf("%s/nostr/addressable?pubkey=%s&kind=30078&d=%s",
		c.relayURL, url.QueryEscape(c.oraclePubkey), url.QueryEscape(dtag))

	c.logger.Debug("Fetching quote from Nostr",
		zap.String("url", reqURL),
		zap.String("dtag", dtag),
	)

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from relay: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // Quote not found (not an error)
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

// CalculateCommitHash computes the BIP-340 tagged hash for a quote
// commit_hash = hash340("DUCAT/commit", oracle_pubkey || chain_network || base_price || base_stamp || thold_price)
func CalculateCommitHash(oraclePubkey, chainNetwork string, basePrice, baseStamp, tholdPrice uint32) (string, error) {
	// BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)
	tag := "DUCAT/commit"
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

// CalculateCollateralRatio computes the collateral ratio as a percentage
// ratio = (thold_price / base_price) * 100
func CalculateCollateralRatio(basePrice, tholdPrice uint32) float64 {
	if basePrice == 0 {
		return 0
	}
	return float64(tholdPrice) / float64(basePrice) * 100.0
}
