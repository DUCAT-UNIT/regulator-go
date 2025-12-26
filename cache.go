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
	Quote     *PriceContract
	CachedAt  time.Time
	ExpiresAt time.Time
}

// QuoteCache provides thread-safe caching for price data and pre-baked quotes
type QuoteCache struct {
	priceMu   sync.RWMutex
	price     *CachedPrice
	quotesMu  sync.RWMutex
	quotes    map[string]*CachedQuote
	maxQuotes int
	quoteTTL  time.Duration
}

// NewQuoteCache creates a new quote cache with default settings
func NewQuoteCache() *QuoteCache {
	return &QuoteCache{
		quotes:    make(map[string]*CachedQuote),
		maxQuotes: 1000,
		quoteTTL:  5 * time.Minute,
	}
}

// SetPrice updates the cached price data
func (c *QuoteCache) SetPrice(basePrice, baseStamp uint32) {
	c.priceMu.Lock()
	defer c.priceMu.Unlock()
	c.price = &CachedPrice{
		BasePrice: basePrice,
		BaseStamp: baseStamp,
		UpdatedAt: time.Now(),
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
func (c *QuoteCache) SetQuote(commitHash string, quote *PriceContract) {
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
		Quote:     quote,
		CachedAt:  time.Now(),
		ExpiresAt: time.Now().Add(c.quoteTTL),
	}
}

// GetQuote retrieves a quote by commit_hash, returns nil if not found or expired
func (c *QuoteCache) GetQuote(commitHash string) *PriceContract {
	c.quotesMu.RLock()
	defer c.quotesMu.RUnlock()

	cached, exists := c.quotes[commitHash]
	if !exists {
		return nil
	}
	if time.Now().After(cached.ExpiresAt) {
		return nil
	}
	return cached.Quote
}

// CleanupExpired removes expired quotes from the cache
func (c *QuoteCache) CleanupExpired() int {
	c.quotesMu.Lock()
	defer c.quotesMu.Unlock()

	now := time.Now()
	cleaned := 0
	for k, v := range c.quotes {
		if now.After(v.ExpiresAt) {
			delete(c.quotes, k)
			cleaned++
		}
	}
	return cleaned
}

// QuoteCount returns the current number of cached quotes
func (c *QuoteCache) QuoteCount() int {
	c.quotesMu.RLock()
	defer c.quotesMu.RUnlock()
	return len(c.quotes)
}
