package store

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are the argon2id cost parameters for new password hashes
// (RFC 9106 second recommended option). Existing hashes carry their own
// parameters. Tests lower them for speed.
var Argon2Params = struct {
	Time, Memory uint32
	Threads      uint8
}{Time: 3, Memory: 64 * 1024, Threads: 4}

const minPassword = 12

func hashPassword(password string) string {
	p := Argon2Params
	salt := make([]byte, 16)
	rand.Read(salt)
	key := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, 32)
	return fmt.Sprintf("argon2id$m=%d,t=%d,p=%d$%s$%s", p.Memory, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

func verifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "argon2id" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[1], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[2])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

var (
	dummyOnce sync.Once
	dummyHash string
)

func validateActor(principal, actor, password string) (string, string, error) {
	principal, actor = strings.TrimSpace(principal), strings.TrimSpace(actor)
	if principal == "" || actor == "" {
		return "", "", invalid("principal and actor must be non-empty")
	}
	if strings.EqualFold(actor, "owner") {
		return "", "", invalid("actor label 'owner' is reserved")
	}
	if utf8.RuneCountInString(principal) > 200 || utf8.RuneCountInString(actor) > 100 {
		return "", "", invalid("principal or actor is too long")
	}
	if utf8.RuneCountInString(password) < minPassword {
		return "", "", invalid("password must contain at least %d characters", minPassword)
	}
	return principal, actor, nil
}

// RegisterActor registers a new actor with its own password. actor_label is
// globally unique.
func (s *Store) RegisterActor(principal, actor, password string) error {
	principal, actor, err := validateActor(principal, actor, password)
	if err != nil {
		return err
	}
	_, err = s.db.Exec("INSERT INTO actors (actor_label, principal_id, password_hash, created_at) VALUES (?, ?, ?, ?)",
		actor, principal, hashPassword(password), s.stamp())
	if err != nil {
		return invalid("actor is already registered")
	}
	return nil
}

// SetActorPassword rotates an actor's password and revokes all of that
// actor's codes and tokens. Other actors are unaffected.
func (s *Store) SetActorPassword(actor, password string) error {
	if utf8.RuneCountInString(password) < minPassword {
		return invalid("password must contain at least %d characters", minPassword)
	}
	return s.tx(func(tx *sql.Tx) error {
		res, err := tx.Exec("UPDATE actors SET password_hash = ?, active = 1 WHERE actor_label = ?",
			hashPassword(password), actor)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return invalid("actor is not registered")
		}
		return revokeActorState(tx, actor)
	})
}

// DeactivateActor disables an actor and revokes its codes and tokens.
func (s *Store) DeactivateActor(actor string) error {
	return s.tx(func(tx *sql.Tx) error {
		res, err := tx.Exec("UPDATE actors SET active = 0 WHERE actor_label = ?", actor)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return invalid("actor is not registered")
		}
		return revokeActorState(tx, actor)
	})
}

func revokeActorState(tx *sql.Tx, actor string) error {
	if _, err := tx.Exec("DELETE FROM oauth_codes WHERE actor_label = ?", actor); err != nil {
		return err
	}
	_, err := tx.Exec("DELETE FROM oauth_tokens WHERE actor_label = ?", actor)
	return err
}

// AuthenticateActor verifies (actor label, password). Unknown, inactive and
// wrong-password cases are indistinguishable to the caller and do comparable
// work.
func (s *Store) AuthenticateActor(actor, password string) (Identity, bool) {
	var principal, hash string
	err := s.db.QueryRow("SELECT principal_id, password_hash FROM actors WHERE actor_label = ? AND active = 1",
		actor).Scan(&principal, &hash)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return Identity{}, false
		}
		dummyOnce.Do(func() { dummyHash = hashPassword("dummy password for timing") })
		verifyPassword(password, dummyHash)
		return Identity{}, false
	}
	if !verifyPassword(password, hash) {
		return Identity{}, false
	}
	return Identity{PrincipalID: principal, ActorLabel: actor}, true
}
