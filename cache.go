package main

import (
	"sync"
	"time"
)

// CachedPrice stores the latest price from webhook
type CachedPrice struct {
	BasePrice uint32
	BaseStamp uint32
	UpdatedAt time.Time
}

// CachedQuote stores a pre-baked quote from Nostr
type CachedQuote struct {
	Quote    *PriceContractResponse
	CachedAt time.Time
}

// QuoteCache provides thread-safe caching for price data and pre-baked quotes
// Quotes are invalidated when the price changes, not by TTL
type QuoteCache struct {
	priceMu   sync.RWMutex
	price     *CachedPrice
	quotesMu  sync.RWMutex
	quotes    map[string]*CachedQuote
	maxQuotes int
}

// NewQuoteCache creates a new quote cache with default settings
func NewQuoteCache() *QuoteCache {
	return &QuoteCache{
		quotes:    make(map[string]*CachedQuote),
		maxQuotes: 1000,
	}
}

// SetPrice updates the cached price data.
//
// When base_price is unchanged, we keep the existing base_stamp so that
// commit_hash lookups continue to match quotes already in local cache and
// on the relay. CRE batches all use the same (price, stamp) snapshot;
// subsequent webhook arrivals for the same price level should not rotate
// the stamp and invalidate every cached quote.
//
// When base_price actually changes, the stamp is updated and all cached
// quotes are flushed because their commit_hashes are no longer valid.
func (c *QuoteCache) SetPrice(basePrice, baseStamp uint32) {
	c.priceMu.Lock()
	priceChanged := c.price == nil || c.price.BasePrice != basePrice
	if priceChanged {
		c.price = &CachedPrice{
			BasePrice: basePrice,
			BaseStamp: baseStamp,
			UpdatedAt: time.Now(),
		}
	} else {
		// Same price — only refresh the liveness timestamp, keep base_stamp stable
		c.price.UpdatedAt = time.Now()
	}
	c.priceMu.Unlock()

	if priceChanged {
		c.quotesMu.Lock()
		c.quotes = make(map[string]*CachedQuote)
		c.quotesMu.Unlock()
	}
}

// GetPrice returns the cached price if it exists and is fresh (< 5 minutes old)
func (c *QuoteCache) GetPrice() *CachedPrice {
	c.priceMu.RLock()
	defer c.priceMu.RUnlock()
	if c.price == nil {
		return nil
	}
	// Check if price is stale (> 5 minutes old)
	if time.Since(c.price.UpdatedAt) > 5*time.Minute {
		return nil
	}
	// Return a copy to prevent race conditions
	return &CachedPrice{
		BasePrice: c.price.BasePrice,
		BaseStamp: c.price.BaseStamp,
		UpdatedAt: c.price.UpdatedAt,
	}
}

// SetQuote stores a quote by commit_hash
func (c *QuoteCache) SetQuote(commitHash string, quote *PriceContractResponse) {
	c.quotesMu.Lock()
	defer c.quotesMu.Unlock()

	// Enforce max size
	if len(c.quotes) >= c.maxQuotes {
		// Remove oldest entry
		var oldestKey string
		var oldestTime time.Time
		for k, v := range c.quotes {
			if oldestKey == "" || v.CachedAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.CachedAt
			}
		}
		if oldestKey != "" {
			delete(c.quotes, oldestKey)
		}
	}

	c.quotes[commitHash] = &CachedQuote{
		Quote:    quote,
		CachedAt: time.Now(),
	}
}

// GetQuote retrieves a quote by commit_hash, returns nil if not found
// Quotes are invalidated by price changes in SetPrice, not by TTL
func (c *QuoteCache) GetQuote(commitHash string) *PriceContractResponse {
	c.quotesMu.RLock()
	defer c.quotesMu.RUnlock()

	cached, exists := c.quotes[commitHash]
	if !exists {
		return nil
	}
	return cached.Quote
}

// QuoteCount returns the current number of cached quotes
func (c *QuoteCache) QuoteCount() int {
	c.quotesMu.RLock()
	defer c.quotesMu.RUnlock()
	return len(c.quotes)
}
