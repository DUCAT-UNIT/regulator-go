package main

import (
	"testing"
)

func TestCalculateCommitHash(t *testing.T) {
	// Test with known values
	oraclePubkey := "0000000000000000000000000000000000000000000000000000000000000000"
	chainNetwork := "mutiny"
	basePrice := uint32(100000)
	baseStamp := uint32(1700000000)
	tholdPrice := uint32(95000)

	hash, err := CalculateCommitHash(oraclePubkey, chainNetwork, basePrice, baseStamp, tholdPrice)
	if err != nil {
		t.Fatalf("Failed to calculate commit hash: %v", err)
	}

	// Hash should be 64 hex characters (32 bytes)
	if len(hash) != 64 {
		t.Errorf("Expected 64 char hash, got %d chars", len(hash))
	}

	// Same inputs should produce same hash (deterministic)
	hash2, _ := CalculateCommitHash(oraclePubkey, chainNetwork, basePrice, baseStamp, tholdPrice)
	if hash != hash2 {
		t.Error("Commit hash should be deterministic")
	}

	// Different thold_price should produce different hash
	hashDiff, _ := CalculateCommitHash(oraclePubkey, chainNetwork, basePrice, baseStamp, 90000)
	if hash == hashDiff {
		t.Error("Different thold_price should produce different hash")
	}
}

func TestCalculateCommitHash_InvalidPubkey(t *testing.T) {
	// Invalid hex
	_, err := CalculateCommitHash("not-hex", "mutiny", 100000, 1700000000, 95000)
	if err == nil {
		t.Error("Expected error for invalid hex pubkey")
	}

	// Wrong length
	_, err = CalculateCommitHash("deadbeef", "mutiny", 100000, 1700000000, 95000)
	if err == nil {
		t.Error("Expected error for wrong length pubkey")
	}
}

func TestCalculateCollateralRatio(t *testing.T) {
	tests := []struct {
		basePrice  uint32
		tholdPrice uint32
		expected   float64
	}{
		{100000, 135000, 135.0},  // 135% collateral ratio
		{100000, 100000, 100.0},  // 100%
		{100000, 150000, 150.0},  // 150%
		{100000, 95000, 95.0},    // 95% (below base)
		{0, 100000, 0.0},         // Zero base price returns 0
	}

	for _, tt := range tests {
		result := CalculateCollateralRatio(tt.basePrice, tt.tholdPrice)
		if result != tt.expected {
			t.Errorf("CalculateCollateralRatio(%d, %d) = %f, expected %f",
				tt.basePrice, tt.tholdPrice, result, tt.expected)
		}
	}
}
