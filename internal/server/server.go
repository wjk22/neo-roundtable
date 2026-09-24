// Package server exposes the OAuth authorization server and the fixed /mcp
// resource over HTTP.
package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wjk22/neo-roundtable/internal/store"
)

// DefaultRedirects are the client callback URIs allowed without configuration.
// Current ChatGPT connectors use a per-connector path under
// https://chatgpt.com/connector/oauth/, allowed here as a prefix pattern.
var DefaultRedirects = []string{
	"https://chatgpt.com/connector_platform_oauth_redirect",
	"https://chatgpt.com/connector/oauth/*",
	"https://claude.ai/api/mcp/auth_callback",
	"https://claude.com/api/mcp/auth_callback",
	"https://antigravity.google/oauth-callback",
}

type Config struct {
	Store *store.Store
	// PublicURL is the canonical https origin, no path. Issuer and audience
	// derive from it, never from request headers.
	PublicURL string
	// SigningKey is 32 bytes and must survive restarts (signs client IDs).
	SigningKey []byte
	// Redirects is the redirect URI allowlist; a trailing '*' is a prefix match.
	Redirects []string
	Logger    *slog.Logger
	// Now overrides the clock in tests.
	Now func() time.Time
}

type Server struct {
	store     *store.Store
	publicURL string
	key       []byte
	redirects []string
	log       *slog.Logger
	now       func() time.Time
	limiter   *limiter
}

func New(c Config) (*Server, error) {
	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") ||
		u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, errors.New("public URL must be a canonical https:// origin with no path")
	}
	if len(c.SigningKey) != 32 {
		return nil, fmt.Errorf("signing key must be 32 bytes, got %d", len(c.SigningKey))
	}
	if err := ValidateAllowlist(c.Redirects); err != nil {
		return nil, err
	}
	s := &Server{
		store:     c.Store,
		publicURL: strings.TrimRight(c.PublicURL, "/"),
		key:       c.SigningKey,
		redirects: c.Redirects,
		log:       c.Logger,
		now:       c.Now,
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	s.limiter = newLimiter(s.now)
	return s, nil
}

// resource is the single fixed MCP endpoint and token audience.
func (s *Server) resource() string { return s.publicURL + "/mcp" }

func method(m string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != m {
			w.Header().Set("Allow", m)
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}
}

// Handler returns the full HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", method("GET", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok"})
	}))
	mux.HandleFunc("/.well-known/oauth-authorization-server", method("GET", s.handleASMetadata))
	mux.HandleFunc("/.well-known/oauth-protected-resource", method("GET", s.handleResourceMetadata))
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", method("GET", s.handleResourceMetadata))
	mux.HandleFunc("/oauth/register", method("POST", s.handleRegister))
	mux.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "POST" {
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleAuthorize(w, r)
	})
	mux.HandleFunc("/oauth/token", method("POST", s.handleToken))
	mux.Handle("/mcp", s.mcpHandler())

	// Web owner interface routes
	mux.HandleFunc("/login", s.handleWebLogin)
	mux.HandleFunc("POST /logout", s.handleWebLogout)
	mux.HandleFunc("GET /{$}", s.handleWebThreads)
	mux.HandleFunc("POST /threads", s.handleWebThreads)
	mux.HandleFunc("GET /threads/{id}", s.handleWebThreadDetail)
	mux.HandleFunc("POST /threads/{id}/messages", s.handleWebPostMessage)
	mux.HandleFunc("POST /threads/{id}/grants", s.handleWebGrantActor)
	mux.HandleFunc("POST /threads/{id}/revokes", s.handleWebRevokeActor)
	mux.HandleFunc("POST /threads/{id}/tombstone", s.handleWebTombstone)
	mux.HandleFunc("POST /threads/{id}/delete", s.handleWebMarkThread)
	mux.HandleFunc("POST /threads/{id}/messages/{msg_id}/delete", s.handleWebMarkMessage)
	mux.HandleFunc("GET /gc", s.handleWebGC)
	mux.HandleFunc("POST /gc", s.handleWebGCConfirm)

	return s.logRequests(mux)
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// logRequests logs method, path and status only (H5): never headers, cookies,
// query strings or bodies.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		s.log.Info("request", "method", r.Method, "path", r.URL.Path, "status", sw.status)
	})
}
