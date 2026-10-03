package fcaptcha

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

// The fake server in fcaptcha_test.go encodes what this package believes the
// verify contract is. These tests check that belief against a real server:
//
//	FCAPTCHA_SECRET=<32+ random bytes> go run ./server-go   # from server-go/
//	FCAPTCHA_TEST_URL=http://localhost:3000 FCAPTCHA_TEST_SECRET=<same> go test .
//
// FCAPTCHA_TEST_SECRET is the signing secret, which is also the verify secret
// when FCAPTCHA_VERIFY_SECRET is unset. Holding it lets the test mint tokens
// directly instead of driving a browser through a challenge.
func integrationClient(t *testing.T) (*Client, string) {
	t.Helper()
	url, secret := os.Getenv("FCAPTCHA_TEST_URL"), os.Getenv("FCAPTCHA_TEST_SECRET")
	if url == "" || secret == "" {
		t.Skip("FCAPTCHA_TEST_URL and FCAPTCHA_TEST_SECRET not set")
	}
	return New(url, secret), secret
}

// mintToken builds a token the way server-go's generateToken does: HMAC-SHA256
// over the sorted-key JSON payload, then unpadded base64url of the payload
// with the signature added.
func mintToken(t *testing.T, secret string, issued time.Time) string {
	t.Helper()
	jti := make([]byte, 16)
	rand.Read(jti)
	data := map[string]any{
		"site_key":  "integration",
		"jti":       hex.EncodeToString(jti),
		"timestamp": issued.Unix(),
		"score":     0.125,
		"ip_hash":   "",
		"hostname":  "example.com",
		"action":    "login",
		"cdata":     "order-42",
	}
	payload, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	data["sig"] = hex.EncodeToString(mac.Sum(nil))
	token, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(token)
}

func TestIntegrationVerify(t *testing.T) {
	c, secret := integrationClient(t)
	ctx := context.Background()
	issued := time.Now().Truncate(time.Second)
	token := mintToken(t, secret, issued)

	got, err := c.Verify(ctx, token, "")
	if err != nil {
		t.Fatal(err)
	}
	want := Result{
		Valid:    true,
		Score:    0.125,
		SiteKey:  "integration",
		Hostname: "example.com",
		Action:   "login",
		CData:    "order-42",
		IssuedAt: issued.UTC(),
	}
	if *got != want {
		t.Errorf("Verify = %+v, want %+v", *got, want)
	}

	again, err := c.Verify(ctx, token, "")
	if err != nil {
		t.Fatal(err)
	}
	if again.Valid || again.Reason != "token_already_used" {
		t.Errorf("replayed Verify = %+v, want token_already_used", again)
	}
}

func TestIntegrationRejections(t *testing.T) {
	c, secret := integrationClient(t)
	ctx := context.Background()

	tests := []struct {
		name, token, remoteIP, reason string
	}{
		{"forged", mintToken(t, "not-the-secret", time.Now()), "", "invalid_signature"},
		{"expired", mintToken(t, secret, time.Now().Add(-10*time.Minute)), "", "expired"},
		// The minted token has an empty ip_hash, which matches no address.
		{"wrong IP", mintToken(t, secret, time.Now()), "203.0.113.10", "ip_mismatch"},
		{"garbage", "!!!", "", "invalid_encoding"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.Verify(ctx, tt.token, tt.remoteIP)
			if err != nil {
				t.Fatal(err)
			}
			if got.Valid || got.Reason != tt.reason {
				t.Errorf("Verify = %+v, want reason %q", got, tt.reason)
			}
		})
	}
}

func TestIntegrationWrongSecret(t *testing.T) {
	c, secret := integrationClient(t)
	_, err := New(c.baseURL, secret+"x").Verify(context.Background(), mintToken(t, secret, time.Now()), "")
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}
