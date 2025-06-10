package traefik_owasp_security

import (
	"context"
	"net/http"
	"strings"
)

var HeaderList = map[string]string{
	// https://owasp.org/www-project-secure-headers/#strict-transport-security
	"Strict-Transport-Security": "max-age=31536000 ; includeSubDomains ; preload",
	// https://owasp.org/www-project-secure-headers/#x-frame-options
	"X-Frame-Options": "sameorigin",
	// https://owasp.org/www-project-secure-headers/#x-content-type-options
	"X-Content-Type-Options": "nosniff",
	// https://owasp.org/www-project-secure-headers/#content-security-policy
	"Content-Security-Policy": "script-src 'self'",
	// https://owasp.org/www-project-secure-headers/#x-permitted-cross-domain-policies
	"X-Permitted-Cross-Domain-Policies": "none",
	// https://owasp.org/www-project-secure-headers/#cross-origin-opener-policy
	"Cross-Origin-Opener-Policy": "same-origin",
	// https://owasp.org/www-project-secure-headers/#cross-origin-resource-policy
	"Cross-Origin-Resource-Policy": "same-origin",
	// https://owasp.org/www-project-secure-headers/#cache-control
	"Cache-Control":                "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0",
	"Referrer-Policy":              "no-referrer-when-downgrade",
	"Cross-Origin-Embedder-Policy": "require-corp",
	"Server":                       "", // Empty to hide server information
	"X-Powered-By":                 "", // Empty to hide powered by information
}

type Config struct {
	DisableCookieHTTPOnly bool `json:"disableCookieHTTPOnly,omitempty"`
	DisableCookieSecure   bool `json:"disableCookieSecure,omitempty"`
	DisableCookieSameSite bool `json:"disableCookieSameSite,omitempty"`
	SkipCookieSecurity    bool `json:"skipCookieSecurity,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		DisableCookieHTTPOnly: false,
		DisableCookieSecure:   false,
		DisableCookieSameSite: false,
		SkipCookieSecurity:    false,
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

	if cookies != "" && !e.config.SkipCookieSecurity {
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
