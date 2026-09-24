package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
)

const (
	// MaxPendingCodes caps in-flight authorization codes.
	MaxPendingCodes = 1000
	AccessTokenTTL  = 3600
	RefreshTokenTTL = 30 * 86400
	CodeTTL         = 60
)

func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// NewToken returns a fresh 256-bit random opaque value.
func NewToken() string { return randomToken() }

// Grant is the persisted authorization bound to a code or token.
type Grant struct {
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	Resource      string
	Identity      Identity
}

func (s *Store) purgeExpired(q interface {
	Exec(string, ...any) (sql.Result, error)
}) error {
	now := s.Now().Unix()
	if _, err := q.Exec("DELETE FROM oauth_codes WHERE expires_at <= ?", now); err != nil {
		return err
	}
	if _, err := q.Exec("DELETE FROM oauth_tokens WHERE expires_at <= ?", now); err != nil {
		return err
	}
	_, err := q.Exec("DELETE FROM owner_sessions WHERE expires_at <= ?", now)
	return err
}

// PurgeExpired deletes expired authorization codes and tokens.
func (s *Store) PurgeExpired() error { return s.purgeExpired(s.db) }

// PutCode stores an authorization code (hashed). It fails with ErrBusy when
// MaxPendingCodes unexpired codes are already outstanding.
func (s *Store) PutCode(code string, g Grant) error {
	return s.tx(func(tx *sql.Tx) error {
		if err := s.purgeExpired(tx); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow("SELECT count(*) FROM oauth_codes").Scan(&n); err != nil {
			return err
		}
		if n >= MaxPendingCodes {
			return ErrBusy
		}
		_, err := tx.Exec("INSERT INTO oauth_codes VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
			hashToken(code), g.ClientID, g.RedirectURI, g.CodeChallenge, g.Resource,
			g.Identity.PrincipalID, g.Identity.ActorLabel, s.Now().Unix()+CodeTTL)
		return err
	})
}

// ConsumeCode atomically removes and returns an unexpired code's grant.
func (s *Store) ConsumeCode(code string) (*Grant, bool) {
	var g *Grant
	err := s.tx(func(tx *sql.Tx) error {
		h := hashToken(code)
		var v Grant
		err := tx.QueryRow("SELECT client_id, redirect_uri, code_challenge, resource, principal_id, actor_label "+
			"FROM oauth_codes WHERE code_hash = ? AND expires_at > ?", h, s.Now().Unix()).
			Scan(&v.ClientID, &v.RedirectURI, &v.CodeChallenge, &v.Resource,
				&v.Identity.PrincipalID, &v.Identity.ActorLabel)
		if err != nil {
			return err
		}
		g = &v
		_, err = tx.Exec("DELETE FROM oauth_codes WHERE code_hash = ?", h)
		return err
	})
	return g, err == nil && g != nil
}

// ConsumeRefresh atomically removes an unexpired refresh token issued to
// clientID whose actor is still active, returning its grant.
func (s *Store) ConsumeRefresh(token, clientID string) (*Grant, bool) {
	var g *Grant
	err := s.tx(func(tx *sql.Tx) error {
		h := hashToken(token)
		var v Grant
		err := tx.QueryRow("SELECT t.client_id, t.resource, t.principal_id, t.actor_label "+
			"FROM oauth_tokens t JOIN actors a ON a.actor_label = t.actor_label "+
			"AND a.principal_id = t.principal_id AND a.active = 1 "+
			"WHERE t.token_hash = ? AND t.token_type = 'refresh' AND t.client_id = ? AND t.expires_at > ?",
			h, clientID, s.Now().Unix()).
			Scan(&v.ClientID, &v.Resource, &v.Identity.PrincipalID, &v.Identity.ActorLabel)
		if err != nil {
			return err
		}
		g = &v
		_, err = tx.Exec("DELETE FROM oauth_tokens WHERE token_hash = ?", h)
		return err
	})
	return g, err == nil && g != nil
}

// PutTokens stores a hashed access/refresh pair for the grant's identity,
// provided the actor is still active.
func (s *Store) PutTokens(g Grant, access, refresh string) error {
	return s.tx(func(tx *sql.Tx) error {
		if err := s.purgeExpired(tx); err != nil {
			return err
		}
		var one int
		err := tx.QueryRow("SELECT 1 FROM actors WHERE actor_label = ? AND principal_id = ? AND active = 1",
			g.Identity.ActorLabel, g.Identity.PrincipalID).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrForbidden
		} else if err != nil {
			return err
		}
		now := s.Now().Unix()
		for _, t := range []struct {
			tok, kind string
			ttl       int64
		}{{access, "access", AccessTokenTTL}, {refresh, "refresh", RefreshTokenTTL}} {
			if _, err := tx.Exec("INSERT INTO oauth_tokens VALUES (?, ?, ?, ?, ?, ?, ?)",
				hashToken(t.tok), t.kind, g.ClientID, g.Resource,
				g.Identity.PrincipalID, g.Identity.ActorLabel, now+t.ttl); err != nil {
				return err
			}
		}
		return nil
	})
}

// AccessIdentity validates an access token, its expiry and audience, and
// returns the principal/actor stored in its grant. It is the only source of
// identity for MCP requests.
func (s *Store) AccessIdentity(token, resource string) (Identity, int64, bool) {
	var who Identity
	var exp int64
	err := s.db.QueryRow("SELECT t.principal_id, t.actor_label, t.expires_at FROM oauth_tokens t "+
		"JOIN actors a ON a.actor_label = t.actor_label AND a.principal_id = t.principal_id "+
		"WHERE t.token_hash = ? AND t.token_type = 'access' AND t.resource = ? "+
		"AND t.expires_at > ? AND a.active = 1",
		hashToken(token), resource, s.Now().Unix()).Scan(&who.PrincipalID, &who.ActorLabel, &exp)
	return who, exp, err == nil
}
