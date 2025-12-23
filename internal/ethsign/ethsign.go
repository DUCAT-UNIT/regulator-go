// Package ethsign provides Ethereum-style message signing and JWT generation
// for CRE gateway authentication.
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
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/sha3"
)

// JWTHeader represents the JWT header
type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// JWTPayload represents the JWT payload
type JWTPayload struct {
	Digest string `json:"digest"`
	Iss    string `json:"iss"`
	Iat    int64  `json:"iat"`
	Exp    int64  `json:"exp"`
	Jti    string `json:"jti"`
}

// GenerateJWT creates a JWT whose header uses alg "ETH" and whose payload contains
// the provided digest, issuer (address), issued-at, expiration (5 minutes) and a
// unique jti. It signs the "header.payload" string using an Ethereum-style
// signing prefix and returns the final token in the form
// "header.payload.signature" where the signature is base64url-encoded.
func GenerateJWT(privKey *ecdsa.PrivateKey, address, digest, jti string) (string, error) {
	now := time.Now().Unix()

	// Create header
	header := JWTHeader{
		Alg: "ETH",
		Typ: "JWT",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Create payload
	payload := JWTPayload{
		Digest: digest,
		Iss:    address,
		Iat:    now,
		Exp:    now + 300, // 5 minutes
		Jti:    jti,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create message to sign
	message := headerB64 + "." + payloadB64

	// Sign with Ethereum prefix
	signature, err := SignEthereumMessage(privKey, message)
	if err != nil {
		return "", err
	}

	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	return message + "." + signatureB64, nil
}

// SignEthereumMessage signs a message using Ethereum's prefixed message format
// and returns a 65-byte signature in the form r||s||v.
// The message is prefixed with "\x19Ethereum Signed Message:\n" and hashed with
// Keccak256 before ECDSA signing; `s` is normalized to the lower half of the
// curve order and `v` is the recovery identifier.
func SignEthereumMessage(privKey *ecdsa.PrivateKey, message string) ([]byte, error) {
	// Create Ethereum signed message prefix
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)

	// Hash with Keccak256
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(prefix))
	messageHash := hash.Sum(nil)

	// Convert to btcec private key for proper signing
	privKeyBytes := privKey.D.Bytes()
	if len(privKeyBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(privKeyBytes):], privKeyBytes)
		privKeyBytes = padded
	}
	btcPrivKey, btcPubKey := btcec.PrivKeyFromBytes(privKeyBytes)

	// Sign using standard ECDSA
	r, s, err := ecdsa.Sign(rand.Reader, privKey, messageHash)
	if err != nil {
		return nil, err
	}

	// Normalize s to lower value (BIP-62)
	curve := btcec.S256()
	halfOrder := new(big.Int).Rsh(curve.Params().N, 1)
	if s.Cmp(halfOrder) > 0 {
		s = new(big.Int).Sub(curve.Params().N, s)
	}

	// Pad r and s to 32 bytes
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	rPadded := make([]byte, 32)
	sPadded := make([]byte, 32)
	copy(rPadded[32-len(rBytes):], rBytes)
	copy(sPadded[32-len(sBytes):], sBytes)

	// Compute recovery ID using proper elliptic curve recovery
	recoveryID, err := computeRecoveryID(btcPrivKey, btcPubKey, messageHash, r, s)
	if err != nil {
		return nil, fmt.Errorf("recovery ID computation failed: %w", err)
	}

	// Format: r || s || v (Ethereum format: v = recoveryID + 27)
	result := make([]byte, 65)
	copy(result[0:32], rPadded)
	copy(result[32:64], sPadded)
	result[64] = byte(recoveryID + 27)

	return result, nil
}

// computeRecoveryID computes the Ethereum recovery ID (0-3) that, when used with
// the provided signature components and message hash, recovers the given public key.
func computeRecoveryID(privKey *btcec.PrivateKey, pubKey *btcec.PublicKey, messageHash []byte, r, s *big.Int) (byte, error) {
	// Get uncompressed public key bytes
	pubKeyBytes := pubKey.SerializeUncompressed()
	targetX := pubKeyBytes[1:33]
	targetY := pubKeyBytes[33:65]

	// Try each recovery ID (0-3)
	for v := byte(0); v < 4; v++ {
		recovered := tryRecoverPublicKey(messageHash, r, s, v)
		if recovered != nil {
			recoveredBytes := recovered.SerializeUncompressed()
			recoveredX := recoveredBytes[1:33]
			recoveredY := recoveredBytes[33:65]

			if bytes.Equal(targetX, recoveredX) && bytes.Equal(targetY, recoveredY) {
				return v, nil
			}
		}
	}

	return 0, fmt.Errorf("failed to compute recovery ID: no valid recovery ID (0-3) matched for pubkey=%x, r=%x, s=%x",
		pubKeyBytes[:8], r.Bytes()[:8], s.Bytes()[:8])
}

// tryRecoverPublicKey attempts to recover a public key from a signature.
func tryRecoverPublicKey(messageHash []byte, r, s *big.Int, recoveryID byte) *btcec.PublicKey {
	curve := btcec.S256()

	// Compute R point x-coordinate
	rX := new(big.Int).Set(r)
	if recoveryID >= 2 {
		// Add N (curve order) for recovery IDs 2 and 3
		rX.Add(rX, curve.Params().N)
	}

	// Check if x is valid (must be < field prime)
	if rX.Cmp(curve.Params().P) >= 0 {
		return nil
	}

	// Compute y from x: y^2 = x^3 + 7 (secp256k1 curve equation)
	ySquared := new(big.Int).Mul(rX, rX)
	ySquared.Mul(ySquared, rX)
	ySquared.Add(ySquared, big.NewInt(7))
	ySquared.Mod(ySquared, curve.Params().P)

	// Compute y = sqrt(y^2) mod P
	y := new(big.Int).ModSqrt(ySquared, curve.Params().P)
	if y == nil {
		return nil
	}

	// Choose y based on recovery ID LSB
	if (y.Bit(0) == 1) != (recoveryID&1 == 1) {
		y.Sub(curve.Params().P, y)
	}

	// Verify point is on curve
	if !curve.IsOnCurve(rX, y) {
		return nil
	}

	// Now recover the public key Q from R point
	// Q = r^-1 * (s*R - e*G) where e is the message hash as integer

	// Compute r^-1 (modular inverse of r mod N)
	rInv := new(big.Int).ModInverse(r, curve.Params().N)
	if rInv == nil {
		return nil
	}

	// e = message hash as big int
	e := new(big.Int).SetBytes(messageHash)

	// Compute s*R
	sRx, sRy := curve.ScalarMult(rX, y, s.Bytes())

	// Compute e*G (G is the generator point)
	eGx, eGy := curve.ScalarBaseMult(e.Bytes())

	// Compute -e*G (negate y coordinate)
	negEGy := new(big.Int).Sub(curve.Params().P, eGy)

	// Compute s*R - e*G = s*R + (-e*G)
	diffX, diffY := curve.Add(sRx, sRy, eGx, negEGy)

	// Compute Q = r^-1 * (s*R - e*G)
	qX, qY := curve.ScalarMult(diffX, diffY, rInv.Bytes())

	// Verify recovered point is on curve
	if !curve.IsOnCurve(qX, qY) {
		return nil
	}

	// Create public key using btcec
	var xFieldVal, yFieldVal btcec.FieldVal
	xFieldVal.SetByteSlice(qX.Bytes())
	yFieldVal.SetByteSlice(qY.Bytes())

	pubKey := btcec.NewPublicKey(&xFieldVal, &yFieldVal)

	return pubKey
}

// PubKeyToAddress derives an Ethereum address from an ECDSA public key.
// It computes the Keccak-256 hash of the uncompressed public key
// (X concatenated with Y), takes the last 20 bytes of the hash, and
// returns the hex-encoded address prefixed with "0x".
func PubKeyToAddress(pubKey *ecdsa.PublicKey) string {
	// Serialize uncompressed public key (remove 0x04 prefix)
	xBytes := pubKey.X.Bytes()
	yBytes := pubKey.Y.Bytes()

	// Pad to 64 bytes if needed
	pubKeyBytes := make([]byte, 64)
	copy(pubKeyBytes[32-len(xBytes):32], xBytes)
	copy(pubKeyBytes[64-len(yBytes):64], yBytes)

	// Keccak256 hash
	hash := sha3.NewLegacyKeccak256()
	hash.Write(pubKeyBytes)
	hashBytes := hash.Sum(nil)

	// Take last 20 bytes for address
	return "0x" + hex.EncodeToString(hashBytes[12:])
}

// GenerateRequestID generates a cryptographically random 32-character hex request ID.
// Returns an error if the system's random number generator fails.
func GenerateRequestID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand.Read failed: %w", err)
	}
	return hex.EncodeToString(b), nil
}
