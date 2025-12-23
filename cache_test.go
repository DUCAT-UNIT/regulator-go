package main

import (
	"testing"
	"time"
)

func TestQuoteCache_SetGetPrice(t *testing.T) {
	cache := NewQuoteCache()

	// Initially no price
	if price := cache.GetPrice(); price != nil {
		t.Error("Expected nil price initially")
	}

	// Set price
	cache.SetPrice(100000, 1700000000)

	// Get price
	price := cache.GetPrice()
	if price == nil {
		t.Fatal("Expected price to be set")
	}
	if price.BasePrice != 100000 {
		t.Errorf("Expected BasePrice 100000, got %d", price.BasePrice)
	}
	if price.BaseStamp != 1700000000 {
		t.Errorf("Expected BaseStamp 1700000000, got %d", price.BaseStamp)
	}
}

func TestQuoteCache_SetGetQuote(t *testing.T) {
	cache := NewQuoteCache()

	commitHash := "abc123def456"

	// Initially no quote
	if quote := cache.GetQuote(commitHash); quote != nil {
		t.Error("Expected nil quote initially")
	}

	// Set quote
	quote := &PriceContractResponse{
		ChainNetwork: "mutiny",
		OraclePubkey: "deadbeef",
		BasePrice:    100000,
		BaseStamp:    1700000000,
		CommitHash:   commitHash,
		TholdPrice:   95000,
	}
	cache.SetQuote(commitHash, quote)

	// Get quote
	retrieved := cache.GetQuote(commitHash)
	if retrieved == nil {
		t.Fatal("Expected quote to be set")
	}
	if retrieved.CommitHash != commitHash {
		t.Errorf("Expected CommitHash %s, got %s", commitHash, retrieved.CommitHash)
	}
	if retrieved.TholdPrice != 95000 {
		t.Errorf("Expected TholdPrice 95000, got %d", retrieved.TholdPrice)
	}
}

func TestQuoteCache_QuoteCount(t *testing.T) {
	cache := NewQuoteCache()

	if count := cache.QuoteCount(); count != 0 {
		t.Errorf("Expected 0 quotes initially, got %d", count)
	}

	cache.SetQuote("hash1", &PriceContractResponse{CommitHash: "hash1"})
	cache.SetQuote("hash2", &PriceContractResponse{CommitHash: "hash2"})

	if count := cache.QuoteCount(); count != 2 {
		t.Errorf("Expected 2 quotes, got %d", count)
	}
}

func TestQuoteCache_CleanupExpired(t *testing.T) {
	cache := NewQuoteCache()
	cache.quoteTTL = 1 * time.Millisecond // Very short TTL for testing

	cache.SetQuote("hash1", &PriceContractResponse{CommitHash: "hash1"})

	// Wait for TTL to expire
	time.Sleep(5 * time.Millisecond)

	cleaned := cache.CleanupExpired()
	if cleaned != 1 {
		t.Errorf("Expected 1 cleaned, got %d", cleaned)
	}

	if count := cache.QuoteCount(); count != 0 {
		t.Errorf("Expected 0 quotes after cleanup, got %d", count)
	}
}

func TestQuoteCache_MaxQuotesEnforced(t *testing.T) {
	cache := NewQuoteCache()
	cache.maxQuotes = 3 // Very small max for testing

	// Add 4 quotes
	cache.SetQuote("hash1", &PriceContractResponse{CommitHash: "hash1"})
	time.Sleep(1 * time.Millisecond) // Ensure different timestamps
	cache.SetQuote("hash2", &PriceContractResponse{CommitHash: "hash2"})
	time.Sleep(1 * time.Millisecond)
	cache.SetQuote("hash3", &PriceContractResponse{CommitHash: "hash3"})
	time.Sleep(1 * time.Millisecond)
	cache.SetQuote("hash4", &PriceContractResponse{CommitHash: "hash4"})

	// Should only have 3 quotes (oldest removed)
	if count := cache.QuoteCount(); count != 3 {
		t.Errorf("Expected 3 quotes (max enforced), got %d", count)
	}

	// Oldest (hash1) should be removed
	if quote := cache.GetQuote("hash1"); quote != nil {
		t.Error("Expected hash1 to be evicted")
	}

	// Newer quotes should still exist
	if quote := cache.GetQuote("hash4"); quote == nil {
		t.Error("Expected hash4 to exist")
	}
}

func TestQuoteCache_PriceStaleness(t *testing.T) {
	cache := NewQuoteCache()

	// Set price
	cache.SetPrice(100000, 1700000000)

	// Manually age the price
	cache.priceMu.Lock()
	cache.price.UpdatedAt = time.Now().Add(-6 * time.Minute)
	cache.priceMu.Unlock()

	// Should return nil for stale price
	if price := cache.GetPrice(); price != nil {
		t.Error("Expected nil for stale price")
	}
}
