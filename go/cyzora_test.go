package cyzora

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func sign(secret, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return hex.EncodeToString(mac.Sum(nil))
}

func TestNormalizePhone(t *testing.T) {
	cases := map[string]string{
		"0712345678":    "254712345678",
		"+254712345678": "254712345678",
		"254712345678":  "254712345678",
		"712345678":     "254712345678",
		"12345":         "",
		"":              "",
	}
	for in, want := range cases {
		if got := NormalizePhone(in); got != want {
			t.Errorf("NormalizePhone(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCents(t *testing.T) {
	c, err := ToCents(2500)
	if err != nil || c != 250000 {
		t.Fatalf("ToCents(2500) = %d, %v", c, err)
	}
	if _, err := ToCents(0); err == nil {
		t.Fatal("ToCents(0) should error")
	}
	if FromCents(250000) != 2500 {
		t.Fatal("FromCents(250000) != 2500")
	}
}

func TestWebhookMultiSecret(t *testing.T) {
	c := New("sk_live_test", WithWebhookSecret("whsec_a"), WithWebhookSecret("whsec_b"))
	body := `{"event":"charge.succeeded","data":{"id":"ch_1"}}`

	if !c.VerifyWebhookSignature([]byte(body), sign("whsec_b", body)) {
		t.Error("expected whsec_b to verify")
	}
	if !c.VerifyWebhookSignature([]byte(body), sign("whsec_a", body)) {
		t.Error("expected whsec_a to verify")
	}
	if c.VerifyWebhookSignature([]byte(body), sign("whsec_wrong", body)) {
		t.Error("wrong secret should not verify")
	}
	if c.VerifyWebhookSignature([]byte(body), "") {
		t.Error("empty signature should not verify")
	}
}

func TestConstructWebhookEvent(t *testing.T) {
	c := New("sk_live_test", WithWebhookSecret("whsec_a"))
	payload := map[string]interface{}{"event": "payout.paid", "data": map[string]interface{}{"amount": 150000}}
	raw, _ := json.Marshal(payload)

	ev, err := c.ConstructWebhookEvent(raw, sign("whsec_a", string(raw)))
	if err != nil {
		t.Fatalf("ConstructWebhookEvent error: %v", err)
	}
	if ev["event"] != "payout.paid" {
		t.Errorf("event = %v, want payout.paid", ev["event"])
	}

	if _, err := c.ConstructWebhookEvent(raw, sign("bad", string(raw))); err == nil {
		t.Error("bad signature should error")
	}
	if _, err := c.ConstructWebhookEvent([]byte("not json"), sign("whsec_a", "not json")); err == nil {
		t.Error("bad json should error")
	}
	if _, err := c.ConstructWebhookEvent(raw, sign("whsec_a", string(raw)), "payout.failed"); err == nil {
		t.Error("mismatched event header should error")
	}
}

func TestEnvDefaults(t *testing.T) {
	t.Setenv("CYZORA_API_BASE", "https://example.test/api/v1/")
	t.Setenv("CYZORA_WEBHOOK_SECRET", "whsec_env_a, whsec_env_b")
	c := New("sk_live_x")
	if c.baseURL != "https://example.test/api/v1" {
		t.Errorf("baseURL = %q", c.baseURL)
	}
	body := `{"event":"charge.succeeded"}`
	if !c.VerifyWebhookSignature([]byte(body), sign("whsec_env_b", body)) {
		t.Error("expected the comma-separated env secret to verify")
	}
}

func TestCreateChargePayload(t *testing.T) {
	var gotMethod, gotPath, gotKey, gotIdem, gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotKey, gotIdem = r.Header.Get("X-API-Key"), r.Header.Get("Idempotency-Key")
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		w.Write([]byte(`{"id":"chg_1","status":"pending"}`))
	}))
	defer server.Close()

	c := New("sk_live_x", WithBaseURL(server.URL))
	_, err := c.CreateCharge(context.Background(), ChargeParams{
		AmountKes: 2500.4, Phone: "0712345678", Network: "tkash", IdempotencyKey: "INV-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotPath != "/charges" {
		t.Errorf("got %s %s", gotMethod, gotPath)
	}
	if gotKey != "sk_live_x" || gotIdem != "INV-1" {
		t.Errorf("headers: key=%q idempotency=%q", gotKey, gotIdem)
	}
	if !strings.Contains(gotBody, `"amount":250100`) || !strings.Contains(gotBody, `"network":"tkash"`) {
		t.Errorf("body = %s", gotBody)
	}
}

func TestPayoutValidation(t *testing.T) {
	c := New("sk_live_x")
	if _, err := c.CreatePayout(context.Background(), PayoutParams{
		AmountKes: 1500.5, Phone: "0712345678",
	}); err == nil {
		t.Error("fractional payout should error")
	}
	if _, err := c.CreatePayout(context.Background(), PayoutParams{
		AmountKes: 1500, DestinationType: "paybill", ShortCode: "100000",
	}); err == nil {
		t.Error("paybill payout without account_ref should error")
	}
}

func TestFeePreviewQuery(t *testing.T) {
	var gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Write([]byte(`{"fee":3300}`))
	}))
	defer server.Close()

	c := New("sk_live_x", WithBaseURL(server.URL))
	if _, err := c.PayoutFeePreview(context.Background(), 2500, "paybill", "collections"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"amount=250000", "destination=paybill", "wallet=collections"} {
		if !strings.Contains(gotQuery, want) {
			t.Errorf("query %q missing %q", gotQuery, want)
		}
	}
	if strings.Contains(gotQuery, "destination_type") {
		t.Errorf("query %q uses the wrong parameter name", gotQuery)
	}
}

func TestPublicStatementAndExport(t *testing.T) {
	var noKey bool
	var csv string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/public/") {
			noKey = r.Header.Get("X-API-Key") == ""
			w.Write([]byte(`{"valid":true}`))
			return
		}
		w.Write([]byte("date,amount\n2026-10-01,2500.00\n"))
	}))
	defer server.Close()

	c := New("sk_live_x", WithBaseURL(server.URL))
	result, err := c.VerifyStatement(context.Background(), "K7PX3MZQ9H2D")
	if err != nil || result["valid"] != true || !noKey {
		t.Fatalf("VerifyStatement: result=%v err=%v noKey=%v", result, err, noKey)
	}
	csv, err = c.ExportCharges(context.Background(), map[string]string{"status": "succeeded"})
	if err != nil || !strings.HasPrefix(csv, "date,amount") {
		t.Fatalf("ExportCharges: csv=%q err=%v", csv, err)
	}
}
