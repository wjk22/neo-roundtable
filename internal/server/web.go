package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/wjk22/neo-roundtable/internal/store"
)

//go:embed templates/*
var templateFS embed.FS

var (
	loginTmpl   = template.Must(template.ParseFS(templateFS, "templates/login.html"))
	threadsTmpl = template.Must(template.ParseFS(templateFS, "templates/threads.html"))
	threadTmpl  = template.Must(template.ParseFS(templateFS, "templates/thread.html"))
	gcTmpl      = template.Must(template.ParseFS(templateFS, "templates/gc.html"))
)

const (
	ownerCookieName = "roundtable_owner_session"
	sessionTTL      = 7 * 86400 // 7 days
)

func (s *Server) csrfToken(rawSecret string) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte("roundtable-csrf:" + rawSecret))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) verifyCSRF(rawSecret, token string) bool {
	if rawSecret == "" || token == "" {
		return false
	}
	expected := s.csrfToken(rawSecret)
	return hmac.Equal([]byte(expected), []byte(token))
}

func (s *Server) setOwnerHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
}

func (s *Server) setSessionCookie(w http.ResponseWriter, rawSecret string) {
	http.SetCookie(w, &http.Cookie{
		Name:     ownerCookieName,
		Value:    rawSecret,
		Path:     "/",
		MaxAge:   sessionTTL,
		HttpOnly: true,
		Secure:   strings.HasPrefix(s.publicURL, "https://"),
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     ownerCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   strings.HasPrefix(s.publicURL, "https://"),
		SameSite: http.SameSiteLaxMode,
	})
}

// requireOwner validates the owner session cookie. It rejects requests with Bearer tokens
// to maintain explicit boundary separation between AI actor tokens and human owner sessions.
func (s *Server) requireOwner(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	s.setOwnerHeaders(w)

	// Reject AI bearer tokens attempting to call owner endpoints
	if r.Header.Get("Authorization") != "" {
		http.Error(w, "Bearer tokens are not permitted on owner web routes", http.StatusUnauthorized)
		return "", "", false
	}

	cookie, err := r.Cookie(ownerCookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return "", "", false
	}

	principal, ok := s.store.ValidateOwnerSession(cookie.Value)
	if !ok {
		s.clearSessionCookie(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return "", "", false
	}

	return principal, cookie.Value, true
}

func (s *Server) ownerDisplayName(principal string) string {
	if strings.EqualFold(principal, "admin") {
		return "Admin"
	}
	return principal
}

func (s *Server) handleWebLogin(w http.ResponseWriter, r *http.Request) {
	s.setOwnerHeaders(w)
	if r.Header.Get("Authorization") != "" {
		http.Error(w, "Bearer tokens are not permitted on owner web routes", http.StatusUnauthorized)
		return
	}

	// If already authenticated, redirect to home
	if cookie, err := r.Cookie(ownerCookieName); err == nil && cookie.Value != "" {
		if _, ok := s.store.ValidateOwnerSession(cookie.Value); ok {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}

	switch r.Method {
	case http.MethodGet:
		data := map[string]any{
			"Principal": "admin",
			"Error":     "",
		}
		loginTmpl.Execute(w, data)

	case http.MethodPost:
		principal := strings.TrimSpace(r.FormValue("principal"))
		password := r.FormValue("password")

		ok, err := s.store.AuthenticateOwner(principal, password)
		if err != nil || !ok {
			w.WriteHeader(http.StatusUnauthorized)
			loginTmpl.Execute(w, map[string]any{
				"Principal": principal,
				"Error":     "Invalid principal or password",
			})
			return
		}

		rawSecret, err := s.store.CreateOwnerSession(principal, sessionTTL)
		if err != nil {
			s.log.Error("failed to create owner session", "err", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		s.setSessionCookie(w, rawSecret)
		http.Redirect(w, r, "/", http.StatusSeeOther)

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleWebLogout(w http.ResponseWriter, r *http.Request) {
	s.setOwnerHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if cookie, err := r.Cookie(ownerCookieName); err == nil && cookie.Value != "" {
		// Validate CSRF before logout if session exists
		if s.verifyCSRF(cookie.Value, r.FormValue("csrf_token")) {
			s.store.RevokeOwnerSession(cookie.Value)
		}
	}
	s.clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleWebThreads(w http.ResponseWriter, r *http.Request) {
	principal, rawSecret, ok := s.requireOwner(w, r)
	if !ok {
		return
	}

	switch r.Method {
	case http.MethodGet:
		threads, err := s.store.ListOwnerThreads(principal)
		if err != nil {
			s.log.Error("list owner threads failed", "err", err)
			http.Error(w, "Failed to load threads", http.StatusInternalServerError)
			return
		}

		actors, err := s.store.ListOwnerActors(principal)
		if err != nil {
			s.log.Error("list owner actors failed", "err", err)
			http.Error(w, "Failed to load actors", http.StatusInternalServerError)
			return
		}

		pendingGC := 0
		if counts, err := s.store.GetGCCounts(principal); err == nil && counts != nil {
			pendingGC = counts.MarkedMessages + counts.MarkedThreads
		}

		data := map[string]any{
			"Principal":      principal,
			"OwnerName":      s.ownerDisplayName(principal),
			"CSRFToken":      s.csrfToken(rawSecret),
			"Threads":        threads,
			"AllActors":      actors,
			"PendingGCCount": pendingGC,
		}
		threadsTmpl.Execute(w, data)

	case http.MethodPost:
		if !s.verifyCSRF(rawSecret, r.FormValue("csrf_token")) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		title := r.FormValue("title")
		r.ParseForm()
		initialActors := r.Form["actors"]

		tid, err := s.store.CreateThread(title, principal)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		for _, a := range initialActors {
			_ = s.store.GrantOwnerActor(tid, principal, a)
		}

		http.Redirect(w, r, "/threads/"+tid, http.StatusSeeOther)

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleWebThreadDetail(w http.ResponseWriter, r *http.Request) {
	principal, rawSecret, ok := s.requireOwner(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	threadID := r.PathValue("id")
	page, err := s.store.GetOwnerThread(threadID, principal)
	if errors.Is(err, store.ErrForbidden) {
		http.Error(w, "Thread not found or forbidden", http.StatusNotFound)
		return
	}
	if err != nil {
		s.log.Error("get owner thread failed", "err", err)
		http.Error(w, "Failed to load thread", http.StatusInternalServerError)
		return
	}

	grantedMap := make(map[string]bool)
	for _, a := range page.GrantedActors {
		grantedMap[a] = true
	}
	var availableActors []string
	for _, a := range page.AllActors {
		if !grantedMap[a] {
			availableActors = append(availableActors, a)
		}
	}

	data := map[string]any{
		"Principal":       principal,
		"OwnerName":       s.ownerDisplayName(principal),
		"CSRFToken":       s.csrfToken(rawSecret),
		"Thread":          page.Thread,
		"Events":          page.Events,
		"GrantedActors":   page.GrantedActors,
		"AvailableActors": availableActors,
	}
	threadTmpl.Execute(w, data)
}

func (s *Server) handleWebPostMessage(w http.ResponseWriter, r *http.Request) {
	principal, rawSecret, ok := s.requireOwner(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.verifyCSRF(rawSecret, r.FormValue("csrf_token")) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	threadID := r.PathValue("id")
	content := r.FormValue("content")

	_, err := s.store.PostOwnerMessage(threadID, principal, content)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, "/threads/"+threadID, http.StatusSeeOther)
}

func (s *Server) handleWebGrantActor(w http.ResponseWriter, r *http.Request) {
	principal, rawSecret, ok := s.requireOwner(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.verifyCSRF(rawSecret, r.FormValue("csrf_token")) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	threadID := r.PathValue("id")
	actor := strings.TrimSpace(r.FormValue("actor"))

	if err := s.store.GrantOwnerActor(threadID, principal, actor); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, "/threads/"+threadID, http.StatusSeeOther)
}

func (s *Server) handleWebRevokeActor(w http.ResponseWriter, r *http.Request) {
	principal, rawSecret, ok := s.requireOwner(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.verifyCSRF(rawSecret, r.FormValue("csrf_token")) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	threadID := r.PathValue("id")
	actor := strings.TrimSpace(r.FormValue("actor"))

	if err := s.store.RevokeOwnerActor(threadID, principal, actor); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, "/threads/"+threadID, http.StatusSeeOther)
}

func (s *Server) handleWebTombstone(w http.ResponseWriter, r *http.Request) {
	principal, rawSecret, ok := s.requireOwner(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.verifyCSRF(rawSecret, r.FormValue("csrf_token")) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	threadID := r.PathValue("id")
	if err := s.store.TombstoneThread(threadID, principal); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, "/threads/"+threadID, http.StatusSeeOther)
}

func (s *Server) handleWebMarkThread(w http.ResponseWriter, r *http.Request) {
	principal, rawSecret, ok := s.requireOwner(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.verifyCSRF(rawSecret, r.FormValue("csrf_token")) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	threadID := r.PathValue("id")
	if err := s.store.MarkThreadDeleted(threadID, principal); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, "/threads/"+threadID, http.StatusSeeOther)
}

func (s *Server) handleWebMarkMessage(w http.ResponseWriter, r *http.Request) {
	principal, rawSecret, ok := s.requireOwner(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.verifyCSRF(rawSecret, r.FormValue("csrf_token")) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	threadID := r.PathValue("id")
	msgIDStr := r.PathValue("msg_id")
	msgID, err := strconv.ParseInt(msgIDStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid message ID", http.StatusBadRequest)
		return
	}

	if err := s.store.MarkMessageDeleted(threadID, principal, msgID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, "/threads/"+threadID, http.StatusSeeOther)
}

func (s *Server) handleWebGC(w http.ResponseWriter, r *http.Request) {
	principal, rawSecret, ok := s.requireOwner(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	counts, err := s.store.GetGCCounts(principal)
	if err != nil {
		s.log.Error("get gc counts failed", "err", err)
		http.Error(w, "Failed to load GC status", http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"Principal":      principal,
		"OwnerName":      s.ownerDisplayName(principal),
		"CSRFToken":      s.csrfToken(rawSecret),
		"MarkedMessages": counts.MarkedMessages,
		"MarkedThreads":  counts.MarkedThreads,
		"PurgedMessages": r.URL.Query().Get("msgs"),
		"PurgedThreads":  r.URL.Query().Get("threads"),
		"Done":           r.URL.Query().Get("done") == "1",
	}
	gcTmpl.Execute(w, data)
}

func (s *Server) handleWebGCConfirm(w http.ResponseWriter, r *http.Request) {
	principal, rawSecret, ok := s.requireOwner(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.verifyCSRF(rawSecret, r.FormValue("csrf_token")) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	stats, err := s.store.GarbageCollect(principal)
	if err != nil {
		s.log.Error("garbage collect failed", "err", err)
		http.Error(w, "Failed to run garbage collection: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/gc?done=1&msgs=%d&threads=%d", stats.PurgedMessages, stats.PurgedThreads), http.StatusSeeOther)
}
