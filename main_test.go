package traefik_owasp_security_headers_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	plugin "github.com/Netsocs-Team/traefik-owasp-security"
)

func TestSecurityHeaders(t *testing.T) {
	handler, _ := plugin.New(nil, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}), plugin.CreateConfig(), "test-plugin")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com", nil)

	handler.ServeHTTP(rec, req)

	for header, value := range plugin.HeaderList {
		if value == "" {
			if rec.Header().Get(header) != "" {
				t.Errorf("Header %s should not be set", header)
			}
		} else {
			if got := rec.Header().Get(header); got != value {
				t.Errorf("Header %s: got %q, want %q", header, got, value)
			}
		}
	}
}

func TestCookieAttributes(t *testing.T) {
	cfg := plugin.CreateConfig()
	handler, _ := plugin.New(nil, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Add("Set-Cookie", "sessionid=abc123")
		rw.WriteHeader(http.StatusOK)
	}), cfg, "test-plugin")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com", nil)

	rec.Header().Set("Set-Cookie", "sessionid=abc123")

	handler.ServeHTTP(rec, req)

	cookie := rec.Header().Get("Set-Cookie")
	if !contains(cookie, "HttpOnly") {
		t.Error("Set-Cookie missing HttpOnly attribute")
	}
	if !contains(cookie, "Secure") {
		t.Error("Set-Cookie missing Secure attribute")
	}
	if !contains(cookie, "SameSite=Lax") {
		t.Error("Set-Cookie missing SameSite attribute")
	}
}

func contains(cookie, attribute string) bool {
	return strings.Contains(strings.ToLower(cookie), strings.ToLower(attribute))
}
