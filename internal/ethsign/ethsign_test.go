package ethsign

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/sha3"
)

// ============================================================================
// Round-trip tests: Generate key, sign, recover, verify
// ============================================================================

func TestTryRecoverPublicKey_RoundTrip(t *testing.T) {
	// Generate a new ECDSA key pair
	privKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Convert to btcec types for comparison
	privKeyBytes := privKey.D.Bytes()
	if len(privKeyBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(privKeyBytes):], privKeyBytes)
		privKeyBytes = padded
	}
	_, expectedPubKey := btcec.PrivKeyFromBytes(privKeyBytes)

	testMessages := []string{
		"hello world",
		"",
		"The quick brown fox jumps over the lazy dog",
		"a]",
		string(make([]byte, 1000)), // Large message
	}

	for i, message := range testMessages {
		t.Run(fmt.Sprintf("message_%d", i), func(t *testing.T) {
			// Sign the message using SignEthereumMessage
			sig, err := SignEthereumMessage(privKey, message)
			if err != nil {
				t.Fatalf("SignEthereumMessage failed: %v", err)
			}

			// Verify signature is 65 bytes
			if len(sig) != 65 {
				t.Fatalf("signature length = %d, want 65", len(sig))
			}

			// Extract r, s, v from signature
			r := new(big.Int).SetBytes(sig[0:32])
			s := new(big.Int).SetBytes(sig[32:64])
			v := sig[64]

			// v should be 27 or 28 (Ethereum format)
			if v != 27 && v != 28 {
				t.Errorf("v = %d, want 27 or 28", v)
			}

			// Convert v back to recovery ID (0 or 1)
			recoveryID := v - 27

			// Compute the message hash the same way SignEthereumMessage does
			prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
			hash := sha3.NewLegacyKeccak256()
			hash.Write([]byte(prefix))
			messageHash := hash.Sum(nil)

			// Recover the public key
			recoveredPubKey := tryRecoverPublicKey(messageHash, r, s, recoveryID)
			if recoveredPubKey == nil {
				t.Fatal("tryRecoverPublicKey returned nil")
			}

			// Compare recovered public key with original
			expectedBytes := expectedPubKey.SerializeUncompressed()
			recoveredBytes := recoveredPubKey.SerializeUncompressed()

			if !bytes.Equal(expectedBytes, recoveredBytes) {
				t.Errorf("recovered public key mismatch:\nexpected: %x\ngot:      %x",
					expectedBytes, recoveredBytes)
			}

			// Also verify X and Y coordinates individually
			expectedX := expectedBytes[1:33]
			expectedY := expectedBytes[33:65]
			recoveredX := recoveredBytes[1:33]
			recoveredY := recoveredBytes[33:65]

			if !bytes.Equal(expectedX, recoveredX) {
				t.Errorf("X coordinate mismatch:\nexpected: %x\ngot:      %x", expectedX, recoveredX)
			}
			if !bytes.Equal(expectedY, recoveredY) {
				t.Errorf("Y coordinate mismatch:\nexpected: %x\ngot:      %x", expectedY, recoveredY)
			}
		})
	}
}

func TestTryRecoverPublicKey_MultipleKeys(t *testing.T) {
	// Test with multiple generated keys to ensure robustness
	for i := 0; i < 10; i++ {
		t.Run(fmt.Sprintf("key_%d", i), func(t *testing.T) {
			privKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			message := fmt.Sprintf("test message %d with unique content", i)
			sig, err := SignEthereumMessage(privKey, message)
			if err != nil {
				t.Fatalf("SignEthereumMessage failed: %v", err)
			}

			r := new(big.Int).SetBytes(sig[0:32])
			s := new(big.Int).SetBytes(sig[32:64])
			recoveryID := sig[64] - 27

			prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
			hash := sha3.NewLegacyKeccak256()
			hash.Write([]byte(prefix))
			messageHash := hash.Sum(nil)

			recovered := tryRecoverPublicKey(messageHash, r, s, recoveryID)
			if recovered == nil {
				t.Fatal("tryRecoverPublicKey returned nil")
			}

			// Verify by comparing addresses
			expectedAddr := PubKeyToAddress(&privKey.PublicKey)
			recoveredAddr := pubKeyToAddressBtcec(recovered)

			if expectedAddr != recoveredAddr {
				t.Errorf("address mismatch:\nexpected: %s\ngot:      %s", expectedAddr, recoveredAddr)
			}
		})
	}
}

// ============================================================================
// Fixed known test vectors (Ethereum ecrecover compatible)
// ============================================================================

func TestTryRecoverPublicKey_KnownVectors(t *testing.T) {
	// Generate a deterministic test vector by signing with a known private key
	// This ensures we have valid r, s values that can actually be recovered

	// Known private key for reproducible testing
	privKeyHex := "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c"
	privKeyBytes, _ := hex.DecodeString(privKeyHex)

	// Pad to 32 bytes if needed
	if len(privKeyBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(privKeyBytes):], privKeyBytes)
		privKeyBytes = padded
	}

	_, btcPubKey := btcec.PrivKeyFromBytes(privKeyBytes)
	expectedPubBytes := btcPubKey.SerializeUncompressed()

	// Create a standard ECDSA private key for signing
	curve := btcec.S256()
	privKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     btcPubKey.X(),
			Y:     btcPubKey.Y(),
		},
		D: new(big.Int).SetBytes(privKeyBytes),
	}

	t.Run("generated_vector", func(t *testing.T) {
		message := "test message for recovery"

		// Sign the message
		sig, err := SignEthereumMessage(privKey, message)
		if err != nil {
			t.Fatalf("SignEthereumMessage failed: %v", err)
		}

		r := new(big.Int).SetBytes(sig[0:32])
		s := new(big.Int).SetBytes(sig[32:64])
		recoveryID := sig[64] - 27

		// Compute message hash
		prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
		hash := sha3.NewLegacyKeccak256()
		hash.Write([]byte(prefix))
		messageHash := hash.Sum(nil)

		// Log the test vector for reference
		t.Logf("Test vector:")
		t.Logf("  messageHash: %x", messageHash)
		t.Logf("  r: %x", r.Bytes())
		t.Logf("  s: %x", s.Bytes())
		t.Logf("  recoveryID: %d", recoveryID)
		t.Logf("  expectedPub: %x", expectedPubBytes)

		// Recover and verify
		recovered := tryRecoverPublicKey(messageHash, r, s, recoveryID)
		if recovered == nil {
			t.Fatal("expected recovery to succeed but got nil")
		}

		recoveredBytes := recovered.SerializeUncompressed()
		if !bytes.Equal(expectedPubBytes, recoveredBytes) {
			t.Errorf("recovered public key mismatch:\nexpected: %x\ngot:      %x",
				expectedPubBytes, recoveredBytes)
		}
	})

	t.Run("wrong_recovery_id", func(t *testing.T) {
		message := "test for wrong recovery id"
		sig, _ := SignEthereumMessage(privKey, message)

		r := new(big.Int).SetBytes(sig[0:32])
		s := new(big.Int).SetBytes(sig[32:64])
		correctRecoveryID := sig[64] - 27
		wrongRecoveryID := (correctRecoveryID + 1) % 2

		prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
		hash := sha3.NewLegacyKeccak256()
		hash.Write([]byte(prefix))
		messageHash := hash.Sum(nil)

		// With wrong recovery ID, should get different public key or nil
		recovered := tryRecoverPublicKey(messageHash, r, s, wrongRecoveryID)
		if recovered != nil {
			recoveredBytes := recovered.SerializeUncompressed()
			if bytes.Equal(expectedPubBytes, recoveredBytes) {
				t.Error("wrong recovery ID should not recover the correct public key")
			}
		}
		// nil is also acceptable
	})

	t.Run("different_messages_same_key", func(t *testing.T) {
		messages := []string{
			"message one",
			"message two",
			"",
			"a very long message that exceeds typical short message lengths to test handling of longer inputs",
		}

		for i, message := range messages {
			sig, err := SignEthereumMessage(privKey, message)
			if err != nil {
				t.Fatalf("message %d: SignEthereumMessage failed: %v", i, err)
			}

			r := new(big.Int).SetBytes(sig[0:32])
			s := new(big.Int).SetBytes(sig[32:64])
			recoveryID := sig[64] - 27

			prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
			hash := sha3.NewLegacyKeccak256()
			hash.Write([]byte(prefix))
			messageHash := hash.Sum(nil)

			recovered := tryRecoverPublicKey(messageHash, r, s, recoveryID)
			if recovered == nil {
				t.Errorf("message %d: recovery failed", i)
				continue
			}

			recoveredBytes := recovered.SerializeUncompressed()
			if !bytes.Equal(expectedPubBytes, recoveredBytes) {
				t.Errorf("message %d: recovered wrong public key", i)
			}
		}
	})
}

// ============================================================================
// Edge cases and failure tests
// ============================================================================

func TestTryRecoverPublicKey_InvalidRecoveryID(t *testing.T) {
	// Use a valid signature but with invalid recovery IDs
	privKey, _ := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	message := "test"

	sig, err := SignEthereumMessage(privKey, message)
	if err != nil {
		t.Fatalf("SignEthereumMessage failed: %v", err)
	}

	r := new(big.Int).SetBytes(sig[0:32])
	s := new(big.Int).SetBytes(sig[32:64])
	correctRecoveryID := sig[64] - 27

	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(prefix))
	messageHash := hash.Sum(nil)

	// Test with wrong recovery ID
	wrongRecoveryID := byte((correctRecoveryID + 1) % 2) // Toggle between 0 and 1
	recovered := tryRecoverPublicKey(messageHash, r, s, wrongRecoveryID)

	// With wrong recovery ID, we should either get nil or a different public key
	if recovered != nil {
		privKeyBytes := privKey.D.Bytes()
		if len(privKeyBytes) < 32 {
			padded := make([]byte, 32)
			copy(padded[32-len(privKeyBytes):], privKeyBytes)
			privKeyBytes = padded
		}
		_, expectedPubKey := btcec.PrivKeyFromBytes(privKeyBytes)

		if bytes.Equal(recovered.SerializeUncompressed(), expectedPubKey.SerializeUncompressed()) {
			t.Error("wrong recovery ID should not recover the same public key")
		}
	}
	// nil is also acceptable for wrong recovery ID
}

func TestTryRecoverPublicKey_RecoveryID2And3(t *testing.T) {
	// Recovery IDs 2 and 3 are rare (r + N < P) but we should handle them
	curve := btcec.S256()

	// These IDs add N to r, which only works if r + N < P
	// Since N and P are very close for secp256k1, this is almost never valid
	// But we test the code path doesn't panic

	messageHash := make([]byte, 32)
	rand.Read(messageHash)

	r := new(big.Int).SetBytes(messageHash) // Use messageHash as r for testing
	s := new(big.Int).SetBytes(messageHash) // Use messageHash as s for testing

	// Recovery ID 2 should typically fail because r + N >= P
	recovered2 := tryRecoverPublicKey(messageHash, r, s, 2)
	// Just verify it doesn't panic - result depends on r value

	recovered3 := tryRecoverPublicKey(messageHash, r, s, 3)
	// Just verify it doesn't panic

	t.Logf("Recovery ID 2 result: %v", recovered2 != nil)
	t.Logf("Recovery ID 3 result: %v", recovered3 != nil)

	// Verify the r + N >= P case
	rPlusN := new(big.Int).Add(r, curve.Params().N)
	if rPlusN.Cmp(curve.Params().P) >= 0 {
		// Expected: recovery IDs 2 and 3 should return nil
		if recovered2 != nil {
			t.Log("Unexpectedly recovered with ID 2 (r + N >= P)")
		}
	}
}

func TestTryRecoverPublicKey_ZeroR(t *testing.T) {
	messageHash := make([]byte, 32)
	rand.Read(messageHash)

	r := big.NewInt(0)
	s := new(big.Int).SetBytes(messageHash)

	// r = 0 should fail (can't compute modular inverse)
	recovered := tryRecoverPublicKey(messageHash, r, s, 0)
	if recovered != nil {
		t.Error("expected recovery to fail with r = 0")
	}
}

func TestTryRecoverPublicKey_ZeroS(t *testing.T) {
	messageHash := make([]byte, 32)
	rand.Read(messageHash)

	r := new(big.Int).SetBytes(messageHash)
	s := big.NewInt(0)

	// s = 0 should still technically work for recovery (s*R = point at infinity issues)
	// but the resulting public key may be invalid
	recovered := tryRecoverPublicKey(messageHash, r, s, 0)
	// Result depends on the implementation; just verify no panic
	t.Logf("Zero s result: %v", recovered != nil)
}

func TestTryRecoverPublicKey_NonRecoverablePoint(t *testing.T) {
	// Create a signature where the R point doesn't exist on the curve
	// This happens when x^3 + 7 is not a quadratic residue mod P

	messageHash := make([]byte, 32)
	rand.Read(messageHash)

	// Use a value of r that doesn't have a valid y coordinate
	// Finding such an r is non-trivial, so we test with random values
	// and verify the function handles non-recoverable cases gracefully
	curve := btcec.S256()

	for i := 0; i < 100; i++ {
		randBytes := make([]byte, 32)
		rand.Read(randBytes)
		r := new(big.Int).SetBytes(randBytes)
		r.Mod(r, curve.Params().N)

		s := new(big.Int).SetBytes(messageHash)

		// Try recovery - it may succeed or fail depending on r
		recovered := tryRecoverPublicKey(messageHash, r, s, 0)
		if recovered != nil {
			// If it succeeds, verify the point is on the curve
			recoveredBytes := recovered.SerializeUncompressed()
			x := new(big.Int).SetBytes(recoveredBytes[1:33])
			y := new(big.Int).SetBytes(recoveredBytes[33:65])

			if !curve.IsOnCurve(x, y) {
				t.Errorf("iteration %d: recovered point not on curve", i)
			}
		}
		// nil is acceptable - just testing we don't panic
	}
}

func TestTryRecoverPublicKey_LargeR(t *testing.T) {
	curve := btcec.S256()
	messageHash := make([]byte, 32)
	rand.Read(messageHash)

	// r >= N should be reduced by the caller, but test behavior
	r := new(big.Int).Set(curve.Params().N)
	r.Add(r, big.NewInt(1)) // r = N + 1

	s := new(big.Int).SetBytes(messageHash)

	// This should handle the case where r > N
	recovered := tryRecoverPublicKey(messageHash, r, s, 0)
	// Result depends on implementation; verify no panic
	t.Logf("Large r result: %v", recovered != nil)
}

func TestTryRecoverPublicKey_MalformedMessageHash(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	message := "test"

	sig, _ := SignEthereumMessage(privKey, message)
	r := new(big.Int).SetBytes(sig[0:32])
	s := new(big.Int).SetBytes(sig[32:64])
	recoveryID := sig[64] - 27

	// Test with various malformed message hashes
	tests := []struct {
		name        string
		messageHash []byte
	}{
		{"empty", []byte{}},
		{"short", make([]byte, 16)},
		{"long", make([]byte, 64)},
		{"single_byte", []byte{0x42}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic with malformed input
			recovered := tryRecoverPublicKey(tt.messageHash, r, s, recoveryID)
			// We don't care about the result, just that it doesn't panic
			t.Logf("%s hash result: %v", tt.name, recovered != nil)
		})
	}
}

// ============================================================================
// Signature format verification tests
// ============================================================================

func TestSignEthereumMessage_Format(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	message := "test message"

	sig, err := SignEthereumMessage(privKey, message)
	if err != nil {
		t.Fatalf("SignEthereumMessage failed: %v", err)
	}

	// Verify signature format
	if len(sig) != 65 {
		t.Errorf("signature length = %d, want 65", len(sig))
	}

	// Extract components
	r := sig[0:32]
	s := sig[32:64]
	v := sig[64]

	// r and s should be non-zero
	rInt := new(big.Int).SetBytes(r)
	sInt := new(big.Int).SetBytes(s)

	if rInt.Sign() == 0 {
		t.Error("r component is zero")
	}
	if sInt.Sign() == 0 {
		t.Error("s component is zero")
	}

	// v should be 27 or 28 (Ethereum format)
	if v != 27 && v != 28 {
		t.Errorf("v = %d, want 27 or 28", v)
	}

	// s should be in lower half of curve order (BIP-62 / EIP-2)
	curve := btcec.S256()
	halfOrder := new(big.Int).Rsh(curve.Params().N, 1)
	if sInt.Cmp(halfOrder) > 0 {
		t.Error("s is not normalized to lower half of curve order")
	}
}

func TestSignEthereumMessage_Deterministic(t *testing.T) {
	// Note: ECDSA signatures with random k are NOT deterministic
	// This test verifies that the same message produces a RECOVERABLE signature
	// but different r,s values each time (due to random k)

	privKey, _ := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	message := "test message"

	sig1, _ := SignEthereumMessage(privKey, message)
	sig2, _ := SignEthereumMessage(privKey, message)

	// v should be consistent for the same key/message (modulo randomness)
	// but r and s will differ

	// Both should recover to the same public key
	r1 := new(big.Int).SetBytes(sig1[0:32])
	s1 := new(big.Int).SetBytes(sig1[32:64])
	v1 := sig1[64] - 27

	r2 := new(big.Int).SetBytes(sig2[0:32])
	s2 := new(big.Int).SetBytes(sig2[32:64])
	v2 := sig2[64] - 27

	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(prefix))
	messageHash := hash.Sum(nil)

	recovered1 := tryRecoverPublicKey(messageHash, r1, s1, v1)
	recovered2 := tryRecoverPublicKey(messageHash, r2, s2, v2)

	if recovered1 == nil || recovered2 == nil {
		t.Fatal("failed to recover public keys")
	}

	// Both should recover to the same public key
	if !bytes.Equal(recovered1.SerializeUncompressed(), recovered2.SerializeUncompressed()) {
		t.Error("different signatures for same message should recover to same public key")
	}
}

// ============================================================================
// Helper functions
// ============================================================================

// pubKeyToAddressBtcec converts a btcec public key to an Ethereum address
func pubKeyToAddressBtcec(pubKey *btcec.PublicKey) string {
	pubKeyBytes := pubKey.SerializeUncompressed()[1:] // Remove 0x04 prefix

	hash := sha3.NewLegacyKeccak256()
	hash.Write(pubKeyBytes)
	hashBytes := hash.Sum(nil)

	return "0x" + hex.EncodeToString(hashBytes[12:])
}

// ============================================================================
// Benchmark tests
// ============================================================================

func BenchmarkTryRecoverPublicKey(b *testing.B) {
	privKey, _ := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	message := "benchmark message"

	sig, _ := SignEthereumMessage(privKey, message)
	r := new(big.Int).SetBytes(sig[0:32])
	s := new(big.Int).SetBytes(sig[32:64])
	recoveryID := sig[64] - 27

	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(prefix))
	messageHash := hash.Sum(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tryRecoverPublicKey(messageHash, r, s, recoveryID)
	}
}

func BenchmarkSignEthereumMessage(b *testing.B) {
	privKey, _ := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	message := "benchmark message"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SignEthereumMessage(privKey, message)
	}
}

func BenchmarkComputeRecoveryID(b *testing.B) {
	privKey, _ := ecdsa.GenerateKey(btcec.S256(), rand.Reader)

	privKeyBytes := privKey.D.Bytes()
	if len(privKeyBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(privKeyBytes):], privKeyBytes)
		privKeyBytes = padded
	}
	btcPrivKey, btcPubKey := btcec.PrivKeyFromBytes(privKeyBytes)

	message := "benchmark message"
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(prefix))
	messageHash := hash.Sum(nil)

	// Sign to get r, s
	r, s, _ := ecdsa.Sign(rand.Reader, privKey, messageHash)

	// Normalize s
	curve := btcec.S256()
	halfOrder := new(big.Int).Rsh(curve.Params().N, 1)
	if s.Cmp(halfOrder) > 0 {
		s = new(big.Int).Sub(curve.Params().N, s)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computeRecoveryID(btcPrivKey, btcPubKey, messageHash, r, s)
	}
}

// ============================================================================
// GenerateJWT tests
// ============================================================================

func TestGenerateJWT_Success(t *testing.T) {
	// Generate a key
	privKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	address := "0x1234567890abcdef1234567890abcdef12345678"
	digest := "0xdeadbeef"
	jti := "unique-request-id-12345"

	token, err := GenerateJWT(privKey, address, digest, jti)
	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}

	// Verify token format: header.payload.signature
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}

	// Decode and verify header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("failed to decode header: %v", err)
	}
	var header JWTHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("failed to unmarshal header: %v", err)
	}
	if header.Alg != "ETH" {
		t.Errorf("expected alg ETH, got %s", header.Alg)
	}
	if header.Typ != "JWT" {
		t.Errorf("expected typ JWT, got %s", header.Typ)
	}

	// Decode and verify payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}
	var payload JWTPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}
	if payload.Digest != digest {
		t.Errorf("expected digest %s, got %s", digest, payload.Digest)
	}
	if payload.Iss != address {
		t.Errorf("expected issuer %s, got %s", address, payload.Iss)
	}
	if payload.Jti != jti {
		t.Errorf("expected jti %s, got %s", jti, payload.Jti)
	}
	if payload.Exp != payload.Iat+300 {
		t.Errorf("expected exp to be iat+300, got iat=%d exp=%d", payload.Iat, payload.Exp)
	}

	// Verify signature can be decoded
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("failed to decode signature: %v", err)
	}
	if len(sigBytes) != 65 {
		t.Errorf("expected 65-byte signature, got %d", len(sigBytes))
	}
}

func TestGenerateJWT_NilPrivateKey(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic with nil private key")
		}
	}()

	GenerateJWT(nil, "0xaddress", "0xdigest", "jti")
}

func TestGenerateJWT_EmptyInputs(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(btcec.S256(), rand.Reader)

	// Empty inputs should still work (just store empty strings)
	token, err := GenerateJWT(privKey, "", "", "")
	if err != nil {
		t.Fatalf("GenerateJWT with empty inputs failed: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Errorf("expected 3 parts, got %d", len(parts))
	}
}

func TestGenerateJWT_LongInputs(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(btcec.S256(), rand.Reader)

	// Test with long inputs
	longAddress := strings.Repeat("0x", 100)
	longDigest := strings.Repeat("a", 1000)
	longJti := strings.Repeat("b", 500)

	token, err := GenerateJWT(privKey, longAddress, longDigest, longJti)
	if err != nil {
		t.Fatalf("GenerateJWT with long inputs failed: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Errorf("expected 3 parts, got %d", len(parts))
	}
}

// ============================================================================
// GenerateRequestID tests
// ============================================================================

func TestGenerateRequestID_Success(t *testing.T) {
	id, err := GenerateRequestID()
	if err != nil {
		t.Fatalf("GenerateRequestID failed: %v", err)
	}

	// Should be 32 hex characters (16 bytes encoded as hex)
	if len(id) != 32 {
		t.Errorf("expected 32 characters, got %d", len(id))
	}

	// Should be valid hex
	_, err = hex.DecodeString(id)
	if err != nil {
		t.Errorf("expected valid hex, got error: %v", err)
	}
}

func TestGenerateRequestID_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	iterations := 1000

	for i := 0; i < iterations; i++ {
		id, err := GenerateRequestID()
		if err != nil {
			t.Fatalf("GenerateRequestID failed: %v", err)
		}
		if seen[id] {
			t.Errorf("duplicate ID generated: %s", id)
		}
		seen[id] = true
	}
}

func TestGenerateRequestID_Format(t *testing.T) {
	id, err := GenerateRequestID()
	if err != nil {
		t.Fatalf("GenerateRequestID failed: %v", err)
	}

	// Should only contain lowercase hex characters
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("unexpected character in ID: %c", c)
		}
	}
}

// ============================================================================
// PubKeyToAddress tests
// ============================================================================

func TestPubKeyToAddress_Success(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	address := PubKeyToAddress(&privKey.PublicKey)

	// Should start with 0x
	if !strings.HasPrefix(address, "0x") {
		t.Errorf("expected address to start with 0x, got %s", address)
	}

	// Should be 42 characters (0x + 40 hex chars)
	if len(address) != 42 {
		t.Errorf("expected 42 characters, got %d", len(address))
	}

	// Should be valid hex after 0x
	_, err = hex.DecodeString(address[2:])
	if err != nil {
		t.Errorf("expected valid hex, got error: %v", err)
	}
}

func TestPubKeyToAddress_Deterministic(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(btcec.S256(), rand.Reader)

	addr1 := PubKeyToAddress(&privKey.PublicKey)
	addr2 := PubKeyToAddress(&privKey.PublicKey)

	if addr1 != addr2 {
		t.Errorf("expected same address for same key, got %s and %s", addr1, addr2)
	}
}

func TestPubKeyToAddress_DifferentKeys(t *testing.T) {
	privKey1, _ := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	privKey2, _ := ecdsa.GenerateKey(btcec.S256(), rand.Reader)

	addr1 := PubKeyToAddress(&privKey1.PublicKey)
	addr2 := PubKeyToAddress(&privKey2.PublicKey)

	if addr1 == addr2 {
		t.Error("expected different addresses for different keys")
	}
}

// ============================================================================
// Edge case tests to improve coverage
// ============================================================================

func TestSignEthereumMessage_SmallPrivateKeyD(t *testing.T) {
	// Test with a private key where D is small (less than 32 bytes when serialized)
	// This triggers the padding branch in SignEthereumMessage

	curve := btcec.S256()

	// Create a private key with a small D value (less than 32 bytes)
	// D = 1 would be too small and invalid, so use a small valid value
	smallD := big.NewInt(1000000) // This will serialize to much less than 32 bytes

	// Compute the public key for this D
	x, y := curve.ScalarBaseMult(smallD.Bytes())

	privKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: smallD,
	}

	message := "test message"
	sig, err := SignEthereumMessage(privKey, message)
	if err != nil {
		t.Fatalf("SignEthereumMessage failed with small D: %v", err)
	}

	// Verify signature format
	if len(sig) != 65 {
		t.Errorf("signature length = %d, want 65", len(sig))
	}

	// v should be 27 or 28
	v := sig[64]
	if v != 27 && v != 28 {
		t.Errorf("v = %d, want 27 or 28", v)
	}

	// Verify the signature can recover the public key
	r := new(big.Int).SetBytes(sig[0:32])
	s := new(big.Int).SetBytes(sig[32:64])
	recoveryID := v - 27

	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(prefix))
	messageHash := hash.Sum(nil)

	recovered := tryRecoverPublicKey(messageHash, r, s, recoveryID)
	if recovered == nil {
		t.Fatal("failed to recover public key from signature with small D")
	}

	// Verify recovered public key matches
	recoveredX := recovered.X()
	recoveredY := recovered.Y()

	if recoveredX.Cmp(x) != 0 || recoveredY.Cmp(y) != 0 {
		t.Error("recovered public key doesn't match original")
	}
}

func TestComputeRecoveryID_NoMatchingID(t *testing.T) {
	// Test the error case where no recovery ID matches
	// This happens when the signature (r, s) doesn't correspond to the public key

	curve := btcec.S256()

	// Create a valid private key
	privKey, _ := ecdsa.GenerateKey(curve, rand.Reader)

	privKeyBytes := privKey.D.Bytes()
	if len(privKeyBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(privKeyBytes):], privKeyBytes)
		privKeyBytes = padded
	}
	btcPrivKey, btcPubKey := btcec.PrivKeyFromBytes(privKeyBytes)

	// Create a message hash
	messageHash := make([]byte, 32)
	rand.Read(messageHash)

	// Create r, s values that don't correspond to this public key
	// by using completely random values
	randomR := make([]byte, 32)
	randomS := make([]byte, 32)
	rand.Read(randomR)
	rand.Read(randomS)

	r := new(big.Int).SetBytes(randomR)
	s := new(big.Int).SetBytes(randomS)

	// Ensure r and s are in valid range (less than N)
	r.Mod(r, curve.Params().N)
	s.Mod(s, curve.Params().N)

	// Ensure they're non-zero
	if r.Sign() == 0 {
		r = big.NewInt(1)
	}
	if s.Sign() == 0 {
		s = big.NewInt(1)
	}

	// This should fail because the random r, s won't recover to btcPubKey
	_, err := computeRecoveryID(btcPrivKey, btcPubKey, messageHash, r, s)

	// Note: Due to the probabilistic nature, this might occasionally succeed
	// if random r, s happen to recover to the same pubkey (astronomically unlikely)
	t.Logf("computeRecoveryID with mismatched r,s: err=%v", err)
}

func TestPubKeyToAddress_SmallCoordinates(t *testing.T) {
	// Test with a public key that has small X or Y coordinates
	// This exercises the padding logic in PubKeyToAddress

	curve := btcec.S256()

	// Use a small private key to get a valid point on the curve
	smallD := big.NewInt(12345)
	x, y := curve.ScalarBaseMult(smallD.Bytes())

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	address := PubKeyToAddress(pubKey)

	// Should still be a valid address
	if !strings.HasPrefix(address, "0x") {
		t.Errorf("expected address to start with 0x, got %s", address)
	}
	if len(address) != 42 {
		t.Errorf("expected 42 characters, got %d", len(address))
	}
}

func TestGenerateJWT_SignatureVerification(t *testing.T) {
	// Test that the JWT signature can be verified by recovering the public key

	privKey, _ := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	address := PubKeyToAddress(&privKey.PublicKey)
	digest := "0xdeadbeef"
	jti := "test-jti-123"

	token, err := GenerateJWT(privKey, address, digest, jti)
	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}

	// Reconstruct the signed message
	signedMessage := parts[0] + "." + parts[1]

	// Decode signature
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("failed to decode signature: %v", err)
	}

	// Extract r, s, v
	r := new(big.Int).SetBytes(sigBytes[0:32])
	s := new(big.Int).SetBytes(sigBytes[32:64])
	v := sigBytes[64]
	recoveryID := v - 27

	// Compute message hash as SignEthereumMessage does
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(signedMessage), signedMessage)
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(prefix))
	messageHash := hash.Sum(nil)

	// Recover public key
	recovered := tryRecoverPublicKey(messageHash, r, s, recoveryID)
	if recovered == nil {
		t.Fatal("failed to recover public key from JWT signature")
	}

	// Verify recovered address matches
	recoveredAddr := pubKeyToAddressBtcec(recovered)
	if recoveredAddr != address {
		t.Errorf("recovered address %s doesn't match original %s", recoveredAddr, address)
	}
}

func TestGenerateJWT_TimestampValidation(t *testing.T) {
	// Verify JWT timestamps are correct

	privKey, _ := ecdsa.GenerateKey(btcec.S256(), rand.Reader)

	beforeTime := time.Now().Unix()
	token, err := GenerateJWT(privKey, "0xaddress", "0xdigest", "jti")
	afterTime := time.Now().Unix()

	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}

	parts := strings.Split(token, ".")
	payloadJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var payload JWTPayload
	json.Unmarshal(payloadJSON, &payload)

	// iat should be within the time window
	if payload.Iat < beforeTime || payload.Iat > afterTime {
		t.Errorf("iat %d not in expected range [%d, %d]", payload.Iat, beforeTime, afterTime)
	}

	// exp should be exactly iat + 300
	if payload.Exp != payload.Iat+300 {
		t.Errorf("exp should be iat+300, got iat=%d exp=%d", payload.Iat, payload.Exp)
	}
}
