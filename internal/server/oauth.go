package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/wjk22/neo-roundtable/internal/store"
)

// ---- Stateless signed client IDs and redirect allowlist (H1) ----

type clientPayload struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	IssuedAt                int64    `json:"iat"`
}

func signClientID(key []byte, p clientPayload) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func verifyClientID(key []byte, id string) (*clientPayload, error) {
	parts := strings.Split(id, ".")
	if len(parts) != 2 {
		return nil, errors.New("invalid client id format")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid client id signature")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(parts[0]))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, errors.New("invalid client id signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("invalid client id payload")
	}
	var p clientPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, errors.New("invalid client id payload")
	}
	return &p, nil
}

// ValidateAllowlist rejects allowlist entries whose only wildcard is not a
// single trailing '*', or that are not absolute https URLs.
func ValidateAllowlist(entries []string) error {
	for _, e := range entries {
		base := strings.TrimSuffix(e, "*")
		if strings.Contains(base, "*") {
			return fmt.Errorf("redirect URI pattern %q: '*' is only allowed as the final character", e)
		}
		u, err := url.Parse(base)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("redirect URI pattern %q must be an absolute https URL", e)
		}
	}
	return nil
}

// redirectAllowed reports whether uri is an https URL matching an allowlist
// entry exactly, or by prefix when the entry ends in '*'.
func redirectAllowed(allow []string, uri string) bool {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" ||
		strings.Contains(uri, "\\") {
		return false
	}
	for _, e := range allow {
		if prefix, ok := strings.CutSuffix(e, "*"); ok {
			if strings.HasPrefix(uri, prefix) {
				return true
			}
		} else if uri == e {
			return true
		}
	}
	return false
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func htmlError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	w.WriteHeader(status)
	fmt.Fprintf(w, "<!doctype html><html><head><meta charset=\"utf-8\"><title>Error</title></head><body><h1>Error</h1><p>%s</p></body></html>", html.EscapeString(msg))
}

// single returns the parameters if none is repeated.
func single(v url.Values) (map[string]string, bool) {
	out := make(map[string]string, len(v))
	for k, vals := range v {
		if len(vals) != 1 {
			return nil, false
		}
		out[k] = vals[0]
	}
	return out, true
}

// ---- Discovery ----

func (s *Server) handleASMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.publicURL,
		"authorization_endpoint":                s.publicURL + "/oauth/authorize",
		"token_endpoint":                        s.publicURL + "/oauth/token",
		"registration_endpoint":                 s.publicURL + "/oauth/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{"mcp"},
	})
}

func (s *Server) handleResourceMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 s.resource(),
		"authorization_servers":    []string{s.publicURL},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{"mcp"},
	})
}

// ---- Registration (stateless: no database access, H1) ----

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		oauthError(w, 400, "invalid_request", "error reading request body")
		return
	}
	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
		AuthMethod   string   `json:"token_endpoint_auth_method"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		oauthError(w, 400, "invalid_request", "malformed JSON body")
		return
	}
	if req.AuthMethod == "" {
		req.AuthMethod = "none"
	}
	if req.AuthMethod != "none" {
		oauthError(w, 400, "invalid_client_metadata", "only token_endpoint_auth_method 'none' is supported")
		return
	}
	if len(req.RedirectURIs) == 0 {
		oauthError(w, 400, "invalid_redirect_uri", "redirect_uris must not be empty")
		return
	}
	for _, uri := range req.RedirectURIs {
		if !redirectAllowed(s.redirects, uri) {
			oauthError(w, 400, "invalid_redirect_uri", "redirect URI is not on the allowlist")
			return
		}
	}
	iat := s.now().Unix()
	id, err := signClientID(s.key, clientPayload{req.RedirectURIs, req.AuthMethod, iat})
	if err != nil {
		oauthError(w, 500, "server_error", "failed to sign client ID")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  id,
		"client_id_issued_at":        iat,
		"redirect_uris":              req.RedirectURIs,
		"token_endpoint_auth_method": "none",
	})
}

// ---- Authorization endpoint ----

type authzRequest struct {
	ClientID, RedirectURI, State, Challenge string
}

// checkRedirect verifies a redirect URI against the signed client ID and the
// allowlist. It is used identically at authorize and token time.
func (s *Server) checkRedirect(clientID, redirectURI string) error {
	p, err := verifyClientID(s.key, clientID)
	if err != nil {
		return errors.New("client ID signature is invalid")
	}
	found := false
	for _, u := range p.RedirectURIs {
		if u == redirectURI {
			found = true
		}
	}
	if !found || !redirectAllowed(s.redirects, redirectURI) {
		return errors.New("redirect_uri is not registered for this client")
	}
	return nil
}

func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, code, desc, state string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		htmlError(w, 400, "Invalid redirect URI.")
		return
	}
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", desc)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// validateAuthz checks the authorization request. It returns (nil, true) if
// it already wrote a response.
func (s *Server) validateAuthz(w http.ResponseWriter, r *http.Request, p map[string]string) (*authzRequest, bool) {
	if p["client_id"] == "" || p["redirect_uri"] == "" {
		htmlError(w, 400, "Missing client_id or redirect_uri.")
		return nil, true
	}
	if err := s.checkRedirect(p["client_id"], p["redirect_uri"]); err != nil {
		htmlError(w, 400, err.Error())
		return nil, true
	}
	req := &authzRequest{p["client_id"], p["redirect_uri"], p["state"], p["code_challenge"]}
	switch {
	case p["response_type"] != "code":
		redirectWithError(w, r, req.RedirectURI, "unsupported_response_type", "response_type must be 'code'", req.State)
	case req.Challenge == "" || p["code_challenge_method"] != "S256":
		redirectWithError(w, r, req.RedirectURI, "invalid_request", "PKCE with code_challenge_method S256 is required", req.State)
	case p["resource"] != "" && p["resource"] != s.resource():
		redirectWithError(w, r, req.RedirectURI, "invalid_target", "resource must be "+s.resource(), req.State)
	default:
		return req, false
	}
	return nil, true
}

var formFields = []string{"response_type", "client_id", "redirect_uri", "state",
	"code_challenge", "code_challenge_method", "resource"}

func (s *Server) renderAuthzForm(w http.ResponseWriter, status int, p map[string]string, redirectURI, notice string) {
	var hidden strings.Builder
	for _, k := range formFields {
		if v, ok := p[k]; ok {
			fmt.Fprintf(&hidden, "<input type=\"hidden\" name=\"%s\" value=\"%s\">", k, html.EscapeString(v))
		}
	}
	msg := ""
	if notice != "" {
		msg = "<p><strong>" + html.EscapeString(notice) + "</strong></p>"
	}
	// form-action allows the form's own origin plus the origin of the already
	// validated redirect URI: Chrome applies form-action to the redirect that
	// follows a form POST, so a bare 'self' would block returning the code.
	formAction := "'self'"
	if u, err := url.Parse(redirectURI); err == nil {
		formAction += " " + u.Scheme + "://" + u.Host
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; form-action "+formAction+"; frame-ancestors 'none'")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize neo-roundtable</title>
<style>body{font-family:sans-serif;max-width:26rem;margin:3rem auto;padding:0 1rem}label{display:block;margin:1rem 0}input:not([type=hidden]){display:block;width:100%%;padding:.4rem;box-sizing:border-box}</style></head><body>
<h1>Authorize neo-roundtable</h1>
<p>Sign in as the actor this client should act as.</p>%s
<form method="post" action="/oauth/authorize">%s
<label>Actor <input type="text" name="actor" autocomplete="username" required maxlength="100"></label>
<label>Password <input type="password" name="password" autocomplete="current-password" required></label>
<button type="submit">Authorize</button></form></body></html>`, msg, hidden.String())
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if err := r.ParseForm(); err != nil {
			htmlError(w, 400, "Malformed form.")
			return
		}
	}
	src := r.URL.Query()
	if r.Method == http.MethodPost {
		src = r.PostForm
	}
	params, ok := single(src)
	if !ok {
		htmlError(w, 400, "Duplicate parameter.")
		return
	}
	req, done := s.validateAuthz(w, r, params)
	if done {
		return
	}
	if r.Method == http.MethodGet {
		s.renderAuthzForm(w, 200, params, req.RedirectURI, "")
		return
	}

	actor, password := params["actor"], params["password"]
	if len(actor) > 100 {
		actor = actor[:100]
	}
	if wait, blocked := s.limiter.blocked(actor); blocked {
		w.Header().Set("Retry-After", fmt.Sprint(int(wait.Seconds())+1))
		s.renderAuthzForm(w, http.StatusTooManyRequests, params, req.RedirectURI, "Too many failed attempts. Try again later.")
		return
	}
	who, ok := s.store.AuthenticateActor(actor, password)
	if !ok {
		s.limiter.fail(actor)
		// Identical for unknown actor, inactive actor and wrong password.
		s.renderAuthzForm(w, http.StatusUnauthorized, params, req.RedirectURI, "Invalid actor or password.")
		return
	}
	s.limiter.reset(actor)

	code := store.NewToken()
	err := s.store.PutCode(code, store.Grant{
		ClientID: req.ClientID, RedirectURI: req.RedirectURI, CodeChallenge: req.Challenge,
		Resource: s.resource(), Identity: who,
	})
	if errors.Is(err, store.ErrBusy) {
		htmlError(w, http.StatusServiceUnavailable, "Server busy.")
		return
	} else if err != nil {
		s.log.Error("store authorization code", "err", err)
		htmlError(w, 500, "Internal error.")
		return
	}
	u, _ := url.Parse(req.RedirectURI)
	q := u.Query()
	q.Set("code", code)
	if req.State != "" {
		q.Set("state", req.State)
	}
	u.RawQuery = q.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// ---- Token endpoint ----

func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, 400, "invalid_request", "malformed form body")
		return
	}
	p, ok := single(r.PostForm)
	if !ok {
		oauthError(w, 400, "invalid_request", "duplicate parameter")
		return
	}
	clientID := p["client_id"]
	if _, err := verifyClientID(s.key, clientID); err != nil {
		oauthError(w, 401, "invalid_client", "unknown client")
		return
	}
	if res, has := p["resource"]; has && res != s.resource() {
		oauthError(w, 400, "invalid_target", "resource must be "+s.resource())
		return
	}

	var g *store.Grant
	switch p["grant_type"] {
	case "authorization_code":
		g, ok = s.store.ConsumeCode(p["code"])
		if !ok {
			oauthError(w, 400, "invalid_grant", "authorization code is invalid or expired")
			return
		}
		v := p["code_verifier"]
		if g.ClientID != clientID || g.RedirectURI != p["redirect_uri"] ||
			s.checkRedirect(clientID, p["redirect_uri"]) != nil ||
			len(v) < 43 || len(v) > 128 ||
			subtle.ConstantTimeCompare([]byte(g.CodeChallenge), []byte(pkceS256(v))) != 1 {
			oauthError(w, 400, "invalid_grant", "authorization code binding mismatch")
			return
		}
	case "refresh_token":
		g, ok = s.store.ConsumeRefresh(p["refresh_token"], clientID)
		if !ok {
			oauthError(w, 400, "invalid_grant", "refresh token is invalid or expired")
			return
		}
	default:
		oauthError(w, 400, "unsupported_grant_type", "unsupported grant_type")
		return
	}
	if g.Resource != s.resource() {
		oauthError(w, 400, "invalid_target", "grant resource mismatch")
		return
	}
	access, refresh := store.NewToken(), store.NewToken()
	if err := s.store.PutTokens(*g, access, refresh); err != nil {
		if errors.Is(err, store.ErrForbidden) {
			oauthError(w, 400, "invalid_grant", "actor is no longer active")
			return
		}
		s.log.Error("store tokens", "err", err)
		oauthError(w, 500, "server_error", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    store.AccessTokenTTL,
		"refresh_token": refresh,
		"scope":         "mcp",
		"resource":      s.resource(),
	})
}
