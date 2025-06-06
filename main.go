package traefik_owasp_security_headers

import (
	"context"
	"net/http"
	"strings"
)

var HeaderList = map[string]string{
	"Strict-Transport-Security":           "max-age=63072000; includeSubDomains; preload",
	"X-Content-Type-Options":              "nosniff",
	"X-Frame-Options":                     "SAMEORIGIN",
	"X-XSS-Protection":                    "1; mode=block",
	"Referrer-Policy":                     "no-referrer-when-downgrade",
	"Content-Security-Policy":             "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';",
	"Permissions-Policy":                  "geolocation=(), microphone=(), camera=()",
	"X-Permitted-Cross-Domain-Policies":   "none",
	"Cross-Origin-Opener-Policy":          "same-origin",
	"Cross-Origin-Resource-Policy":        "same-origin",
	"Cross-Origin-Embedder-Policy":        "require-corp",
	"Cache-Control":                       "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0",
	"Server":                              "", // Empty to hide server information
	"X-Powered-By":                        "", // Empty to hide powered by information
	"Pragma":                              "no-cache",
	"Content-Security-Policy-Report-Only": "default-src 'self'; script-src 'self'; style-src 'self'; form-action 'self'; report-uri /csp-report-endpoint",
	"Expect-CT":                           "max-age=31536000, enforce",
	"Feature-Policy":                      "geolocation 'none'; microphone 'none'; camera 'none'",
}

type Config struct {
	DisableCookieHTTPOnly bool `json:"disableCookieHTTPOnly,omitempty"`
	DisableCookieSecure   bool `json:"disableCookieSecure,omitempty"`
	DisableCookieSameSite bool `json:"disableCookieSameSite,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		// ...
	}
}

// TraefikOwaspSecurityHeaders a plugin.
type TraefikOwaspSecurityHeaders struct {
	next   http.Handler
	name   string
	config *Config
}

// New created a new plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {

	return &TraefikOwaspSecurityHeaders{
		next:   next,
		name:   name,
		config: config,
	}, nil
}

func (e *TraefikOwaspSecurityHeaders) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Set security headers

	for header, value := range HeaderList {
		if value != "" {
			rw.Header().Set(header, value)
		} else {
			rw.Header().Del(header) // Remove header if value is empty
		}
	}

	// check if Set-Cookie exists and apply HTTPOnly, Secure, and SameSite attributes if configured.
	// No replace the cookie, only add attributes if they are not already set.
	cookies := rw.Header().Get("Set-Cookie")

	if cookies != "" {
		cookies = e.applyCookieSecurity(cookies)
		rw.Header().Set("Set-Cookie", cookies)
	}

	e.next.ServeHTTP(rw, req)
}

func (e *TraefikOwaspSecurityHeaders) applyCookieSecurity(cookies string) string {
	if !e.config.DisableCookieHTTPOnly {
		if !contains(cookies, "HttpOnly") {
			cookies = cookies + "; HttpOnly"
		}

	}
	if !e.config.DisableCookieSecure {
		if !contains(cookies, "Secure") {
			cookies = cookies + "; Secure"
		}

	}
	if !e.config.DisableCookieSameSite {
		if !contains(cookies, "SameSite") {
			cookies = cookies + "; SameSite=Lax"
		}
	}
	return cookies
}

func contains(cookie, attribute string) bool {
	return strings.Contains(strings.ToLower(cookie), strings.ToLower(attribute))
}
