package fairplay

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"os"
	"testing"
)

// TestRealSINFVector checks a privately held, independently verified SINF.
// Neither the SINF nor the logical key belongs in the repository. Set both
// environment variables to run it:
//
//	IPATOOL_REAL_SINF_PATH=/private/path/app.sinf
//	IPATOOL_REAL_LOGICAL_KEY_SHA256=<64 hexadecimal characters>
//
// The expected digest verifies a candidate key; it cannot recover that key.
func TestRealSINFVector(t *testing.T) {
	path := os.Getenv("IPATOOL_REAL_SINF_PATH")
	wantHex := os.Getenv("IPATOOL_REAL_LOGICAL_KEY_SHA256")
	if path == "" && wantHex == "" {
		t.Skip("private real-SINF vector not configured")
	}
	if path == "" || wantHex == "" {
		t.Fatal("both real-SINF vector environment variables are required")
	}
	want, err := hex.DecodeString(wantHex)
	if err != nil || len(want) != sha256.Size {
		t.Fatal("expected logical-key SHA-256 must be 64 hexadecimal characters")
	}
	sinf, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read private SINF fixture:", err)
	}
	defer clear(sinf)
	material, err := ResolveLogicalKey(sinf)
	if err != nil {
		t.Fatalf("real SINF key recovery failed: %v", err)
	}
	defer clear(material.LogicalKey[:])
	got := sha256.Sum256(material.LogicalKey[:])
	if subtle.ConstantTimeCompare(got[:], want) != 1 {
		t.Fatal("real SINF logical key does not match the expected SHA-256")
	}
}
