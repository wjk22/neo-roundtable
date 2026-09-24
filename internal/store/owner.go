package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// OwnerThread represents a thread as viewed by the owner.
type OwnerThread struct {
	ID               string   `json:"id"`
	Title            *string  `json:"title"`
	CreatedAt        string   `json:"created_at"`
	OwnerPrincipalID string   `json:"owner_principal_id"`
	TombstonedAt     *string  `json:"tombstoned_at,omitempty"`
	MarkedDeletedAt  *string  `json:"marked_deleted_at,omitempty"`
	PurgedAt         *string  `json:"purged_at,omitempty"`
	GrantedActors    []string `json:"granted_actors"`
}

// OwnerThreadPage is the complete thread detail view for the owner.
type OwnerThreadPage struct {
	Thread        OwnerThread `json:"thread"`
	Events        []Event     `json:"events"`
	GrantedActors []string    `json:"granted_actors"`
	AllActors     []string    `json:"all_actors"`
}

// SetOwnerPassword sets or rotates the password for a human owner principal.
// It invalidates all active web sessions for that principal.
func (s *Store) SetOwnerPassword(principal, password string) error {
	principal = strings.TrimSpace(principal)
	if principal == "" {
		return invalid("principal must be non-empty")
	}
	if utf8.RuneCountInString(principal) > 200 {
		return invalid("principal is too long")
	}
	if utf8.RuneCountInString(password) < minPassword {
		return invalid("password must contain at least %d characters", minPassword)
	}

	hash := hashPassword(password)
	return s.tx(func(tx *sql.Tx) error {
		_, err := tx.Exec(`
INSERT INTO owner_credentials (principal_id, password_hash, created_at)
VALUES (?, ?, ?)
ON CONFLICT(principal_id) DO UPDATE SET password_hash = excluded.password_hash, created_at = excluded.created_at`,
			principal, hash, s.stamp())
		if err != nil {
			return err
		}
		// Invalidate active sessions
		_, err = tx.Exec("DELETE FROM owner_sessions WHERE principal_id = ?", principal)
		return err
	})
}

// AuthenticateOwner verifies the owner password.
func (s *Store) AuthenticateOwner(principal, password string) (bool, error) {
	principal = strings.TrimSpace(principal)
	var hash string
	err := s.db.QueryRow("SELECT password_hash FROM owner_credentials WHERE principal_id = ?", principal).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		dummyOnce.Do(func() { dummyHash = hashPassword("dummy password for timing") })
		verifyPassword(password, dummyHash)
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return verifyPassword(password, hash), nil
}

// CreateOwnerSession generates a cryptographically random session secret,
// stores its SHA-256 hash in SQLite, and returns the raw secret for the cookie.
func (s *Store) CreateOwnerSession(principal string, ttlSeconds int64) (string, error) {
	principal = strings.TrimSpace(principal)
	if principal == "" {
		return "", invalid("principal must be non-empty")
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	rawSecret := base64.RawURLEncoding.EncodeToString(b)
	sessionHash := hashToken(rawSecret)
	expiresAt := s.Now().Unix() + ttlSeconds

	_, err := s.db.Exec("INSERT INTO owner_sessions (session_hash, principal_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
		sessionHash, principal, expiresAt, s.stamp())
	if err != nil {
		return "", err
	}
	return rawSecret, nil
}

// ValidateOwnerSession validates the raw session secret from the cookie and
// returns the principal if valid and unexpired.
func (s *Store) ValidateOwnerSession(rawSecret string) (string, bool) {
	if rawSecret == "" {
		return "", false
	}
	sessionHash := hashToken(rawSecret)
	var principal string
	var expiresAt int64
	err := s.db.QueryRow("SELECT principal_id, expires_at FROM owner_sessions WHERE session_hash = ?", sessionHash).
		Scan(&principal, &expiresAt)
	if err != nil || expiresAt <= s.Now().Unix() {
		return "", false
	}
	return principal, true
}

// RevokeOwnerSession invalidates a session by its raw cookie secret.
func (s *Store) RevokeOwnerSession(rawSecret string) error {
	if rawSecret == "" {
		return nil
	}
	sessionHash := hashToken(rawSecret)
	_, err := s.db.Exec("DELETE FROM owner_sessions WHERE session_hash = ?", sessionHash)
	return err
}

// ListOwnerThreads returns all threads owned by ownerID, including tombstoned and marked ones,
// ordered by creation time descending.
func (s *Store) ListOwnerThreads(ownerID string) ([]OwnerThread, error) {
	rows, err := s.db.Query(`
SELECT id, title, created_at, owner_principal_id, tombstoned_at, marked_deleted_at, purged_at
FROM threads
WHERE owner_principal_id = ?
ORDER BY created_at DESC, id`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var threads []OwnerThread
	for rows.Next() {
		var t OwnerThread
		var tomb, marked, purged sql.NullString
		if err := rows.Scan(&t.ID, &t.Title, &t.CreatedAt, &t.OwnerPrincipalID, &tomb, &marked, &purged); err != nil {
			return nil, err
		}
		if tomb.Valid {
			t.TombstonedAt = &tomb.String
		}
		if marked.Valid {
			t.MarkedDeletedAt = &marked.String
		}
		if purged.Valid {
			t.PurgedAt = &purged.String
		}
		threads = append(threads, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Populate granted actors
	for i := range threads {
		aclRows, err := s.db.Query("SELECT actor_label FROM thread_acl WHERE thread_id = ? ORDER BY actor_label", threads[i].ID)
		if err != nil {
			return nil, err
		}
		for aclRows.Next() {
			var act string
			if err := aclRows.Scan(&act); err != nil {
				aclRows.Close()
				return nil, err
			}
			threads[i].GrantedActors = append(threads[i].GrantedActors, act)
		}
		aclRows.Close()
	}

	return threads, nil
}

// GetOwnerThread returns full audit history of an owned thread.
func (s *Store) GetOwnerThread(threadID, ownerID string) (*OwnerThreadPage, error) {
	var t OwnerThread
	var tomb, marked, purged sql.NullString
	err := s.db.QueryRow(`
SELECT id, title, created_at, owner_principal_id, tombstoned_at, marked_deleted_at, purged_at
FROM threads
WHERE id = ?`, threadID).Scan(&t.ID, &t.Title, &t.CreatedAt, &t.OwnerPrincipalID, &tomb, &marked, &purged)
	if errors.Is(err, sql.ErrNoRows) || (t.OwnerPrincipalID != ownerID) {
		return nil, ErrForbidden
	}
	if err != nil {
		return nil, err
	}
	if tomb.Valid {
		t.TombstonedAt = &tomb.String
	}
	if marked.Valid {
		t.MarkedDeletedAt = &marked.String
	}
	if purged.Valid {
		t.PurgedAt = &purged.String
	}

	// Granted actors
	aclRows, err := s.db.Query("SELECT actor_label FROM thread_acl WHERE thread_id = ? ORDER BY actor_label", threadID)
	if err != nil {
		return nil, err
	}
	for aclRows.Next() {
		var act string
		if err := aclRows.Scan(&act); err != nil {
			aclRows.Close()
			return nil, err
		}
		t.GrantedActors = append(t.GrantedActors, act)
	}
	aclRows.Close()

	// All registered actors under this owner
	allActors, err := s.ListOwnerActors(ownerID)
	if err != nil {
		return nil, err
	}

	// Events
	rows, err := s.db.Query(eventSelect+" WHERE e.thread_id = ? ORDER BY e.id ASC", threadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		// Render reference for owner if ref_id exists
		if e.RefID != nil {
			ref := &Reference{EventID: *e.RefID}
			src, err := scanEvent(s.db.QueryRow(eventSelect+" WHERE e.id = ?", *e.RefID))
			if err == nil {
				// Check owner of source thread
				var srcOwner string
				if err := s.db.QueryRow("SELECT owner_principal_id FROM threads WHERE id = ?", src.ThreadID).Scan(&srcOwner); err == nil && srcOwner == ownerID {
					ref.Accessible = true
					summary := src.EventSummary
					ref.Event = &summary
				}
			}
			e.Reference = ref
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return &OwnerThreadPage{
		Thread:        t,
		Events:        events,
		GrantedActors: t.GrantedActors,
		AllActors:     allActors,
	}, nil
}

// PostOwnerMessage appends a human message with server-derived actor_label='owner'.
func (s *Store) PostOwnerMessage(threadID, ownerID, content string) (*Event, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil, invalid("content is required")
	}
	if utf8.RuneCountInString(content) > MaxMessage {
		return nil, invalid("content exceeds %d bytes", MaxMessage)
	}

	var ev Event
	err := s.tx(func(tx *sql.Tx) error {
		var owner string
		var tomb, marked, purged sql.NullString
		err := tx.QueryRow("SELECT owner_principal_id, tombstoned_at, marked_deleted_at, purged_at FROM threads WHERE id = ?", threadID).
			Scan(&owner, &tomb, &marked, &purged)
		if errors.Is(err, sql.ErrNoRows) || owner != ownerID {
			return ErrForbidden
		}
		if err != nil {
			return err
		}
		if tomb.Valid {
			return invalid("thread is tombstoned")
		}
		if marked.Valid {
			return invalid("thread is marked for deletion")
		}
		if purged.Valid {
			return invalid("thread is purged")
		}

		stamp := s.stamp()
		res, err := tx.Exec(`
INSERT INTO events (thread_id, created_at, principal_id, actor_label, ref_id, relation, event_kind)
VALUES (?, ?, ?, 'owner', NULL, NULL, 'entry')`,
			threadID, stamp, ownerID)
		if err != nil {
			return err
		}
		id, err := res.LastInsertId()
		if err != nil {
			return err
		}

		if _, err := tx.Exec("INSERT INTO event_payloads (event_id, content) VALUES (?, ?)", id, content); err != nil {
			return err
		}

		ev, err = scanEvent(tx.QueryRow(eventSelect+" WHERE e.id = ?", id))
		return err
	})
	if err != nil {
		return nil, err
	}
	return &ev, nil
}

// TombstoneThread atomically appends a thread_tombstoned event and marks threads.tombstoned_at.
// It is idempotent: a second call returns cleanly without appending duplicate events.
func (s *Store) TombstoneThread(threadID, ownerID string) error {
	return s.tx(func(tx *sql.Tx) error {
		var owner string
		var tomb, marked, purged sql.NullString
		err := tx.QueryRow("SELECT owner_principal_id, tombstoned_at, marked_deleted_at, purged_at FROM threads WHERE id = ?", threadID).
			Scan(&owner, &tomb, &marked, &purged)
		if errors.Is(err, sql.ErrNoRows) || owner != ownerID {
			return ErrForbidden
		}
		if err != nil {
			return err
		}
		if marked.Valid {
			return invalid("thread is marked for deletion")
		}
		if purged.Valid {
			return invalid("thread is purged")
		}
		if tomb.Valid {
			// Idempotent: already tombstoned
			return nil
		}

		stamp := s.stamp()
		// Insert tombstone event (metadata entry)
		_, err = tx.Exec(`
INSERT INTO events (thread_id, created_at, principal_id, actor_label, ref_id, relation, event_kind)
VALUES (?, ?, ?, 'owner', NULL, NULL, 'thread_tombstoned')`,
			threadID, stamp, ownerID)
		if err != nil {
			return fmt.Errorf("append tombstone event: %w", err)
		}

		// Update query projection
		_, err = tx.Exec("UPDATE threads SET tombstoned_at = ? WHERE id = ?", stamp, threadID)
		if err != nil {
			return fmt.Errorf("set thread tombstone: %w", err)
		}
		return nil
	})
}

// GrantOwnerActor grants access to an actor registered under the owner's principal.
func (s *Store) GrantOwnerActor(threadID, ownerID, actorLabel string) error {
	return s.tx(func(tx *sql.Tx) error {
		var owner string
		var tomb, marked, purged sql.NullString
		err := tx.QueryRow("SELECT owner_principal_id, tombstoned_at, marked_deleted_at, purged_at FROM threads WHERE id = ?", threadID).
			Scan(&owner, &tomb, &marked, &purged)
		if errors.Is(err, sql.ErrNoRows) || owner != ownerID {
			return ErrForbidden
		}
		if err != nil {
			return err
		}
		if tomb.Valid {
			return invalid("thread is tombstoned")
		}
		if marked.Valid {
			return invalid("thread is marked for deletion")
		}
		if purged.Valid {
			return invalid("thread is purged")
		}

		var principal string
		err = tx.QueryRow("SELECT principal_id FROM actors WHERE actor_label = ? AND active = 1", actorLabel).
			Scan(&principal)
		if err != nil {
			return invalid("actor is not registered")
		}
		if principal != ownerID {
			return invalid("actor does not belong to thread owner")
		}

		_, err = tx.Exec("INSERT INTO thread_acl (thread_id, principal_id, actor_label, created_at) VALUES (?, ?, ?, ?)",
			threadID, principal, actorLabel, s.stamp())
		if err != nil {
			return invalid("grant already exists")
		}
		return nil
	})
}

// RevokeOwnerActor revokes access for an actor from an owned thread.
func (s *Store) RevokeOwnerActor(threadID, ownerID, actorLabel string) error {
	return s.tx(func(tx *sql.Tx) error {
		var owner string
		var tomb, marked, purged sql.NullString
		err := tx.QueryRow("SELECT owner_principal_id, tombstoned_at, marked_deleted_at, purged_at FROM threads WHERE id = ?", threadID).
			Scan(&owner, &tomb, &marked, &purged)
		if errors.Is(err, sql.ErrNoRows) || owner != ownerID {
			return ErrForbidden
		}
		if err != nil {
			return err
		}
		if tomb.Valid {
			return invalid("thread is tombstoned")
		}
		if marked.Valid {
			return invalid("thread is marked for deletion")
		}
		if purged.Valid {
			return invalid("thread is purged")
		}

		res, err := tx.Exec("DELETE FROM thread_acl WHERE thread_id = ? AND actor_label = ?", threadID, actorLabel)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return invalid("grant does not exist")
		}
		return nil
	})
}

// MarkMessageDeleted marks a message or reference event for deletion.
// It is idempotent and immediately hides the message payload.
func (s *Store) MarkMessageDeleted(threadID, ownerID string, eventID int64) error {
	return s.tx(func(tx *sql.Tx) error {
		var owner string
		var purged sql.NullString
		err := tx.QueryRow("SELECT owner_principal_id, purged_at FROM threads WHERE id = ?", threadID).
			Scan(&owner, &purged)
		if errors.Is(err, sql.ErrNoRows) || owner != ownerID {
			return ErrForbidden
		}
		if err != nil {
			return err
		}
		if purged.Valid {
			return invalid("thread is purged")
		}

		var eventThread string
		err = tx.QueryRow("SELECT thread_id FROM events WHERE id = ?", eventID).Scan(&eventThread)
		if errors.Is(err, sql.ErrNoRows) || eventThread != threadID {
			return invalid("message not found in thread")
		}
		if err != nil {
			return err
		}

		// Idempotent insertion
		_, err = tx.Exec("INSERT OR IGNORE INTO event_deletions (event_id, marked_at) VALUES (?, ?)",
			eventID, s.stamp())
		return err
	})
}

// MarkThreadDeleted marks an active or tombstoned thread for deletion.
// It atomically closes the thread to reads and posts, and is idempotent.
func (s *Store) MarkThreadDeleted(threadID, ownerID string) error {
	return s.tx(func(tx *sql.Tx) error {
		var owner string
		var marked, purged sql.NullString
		err := tx.QueryRow("SELECT owner_principal_id, marked_deleted_at, purged_at FROM threads WHERE id = ?", threadID).
			Scan(&owner, &marked, &purged)
		if errors.Is(err, sql.ErrNoRows) || owner != ownerID {
			return ErrForbidden
		}
		if err != nil {
			return err
		}
		if purged.Valid || marked.Valid {
			// Idempotent: already marked or purged
			return nil
		}

		_, err = tx.Exec("UPDATE threads SET marked_deleted_at = ? WHERE id = ?", s.stamp(), threadID)
		return err
	})
}

type GCCounts struct {
	MarkedMessages int `json:"marked_messages"`
	MarkedThreads  int `json:"marked_threads"`
}

// GetGCCounts returns counts of marked messages and threads awaiting purge for an owner.
func (s *Store) GetGCCounts(ownerID string) (*GCCounts, error) {
	counts := &GCCounts{}
	err := s.db.QueryRow(`
SELECT count(DISTINCT p.event_id)
FROM event_payloads p
JOIN events e ON e.id = p.event_id
JOIN threads t ON t.id = e.thread_id
JOIN event_deletions d ON d.event_id = e.id
WHERE t.owner_principal_id = ?
  AND t.purged_at IS NULL
  AND t.marked_deleted_at IS NULL`, ownerID).Scan(&counts.MarkedMessages)
	if err != nil {
		return nil, err
	}

	err = s.db.QueryRow(`
SELECT count(*)
FROM threads
WHERE owner_principal_id = ?
  AND (marked_deleted_at IS NOT NULL OR purged_at IS NOT NULL)`, ownerID).Scan(&counts.MarkedThreads)
	if err != nil {
		return nil, err
	}

	return counts, nil
}

type GCStats struct {
	PurgedMessages int `json:"purged_messages"`
	PurgedThreads  int `json:"purged_threads"`
}

// GarbageCollect permanently removes marked message payloads, clears metadata on marked threads,
// and runs SQLite secure deletion and compaction.
func (s *Store) GarbageCollect(ownerID string) (*GCStats, error) {
	stats := &GCStats{}

	err := s.tx(func(tx *sql.Tx) error {
		// 1. Delete marked payloads for individually marked messages
		res, err := tx.Exec(`
DELETE FROM event_payloads
WHERE event_id IN (
    SELECT p.event_id
    FROM event_payloads p
    JOIN events e ON e.id = p.event_id
    JOIN threads t ON t.id = e.thread_id
    JOIN event_deletions d ON d.event_id = e.id
    WHERE t.owner_principal_id = ?
      AND t.marked_deleted_at IS NULL
      AND t.purged_at IS NULL
)`, ownerID)
		if err != nil {
			return fmt.Errorf("delete marked payloads: %w", err)
		}
		n, _ := res.RowsAffected()
		stats.PurgedMessages = int(n)

		// 2. Identify marked/purged threads to delete completely
		threadRows, err := tx.Query(`
SELECT id FROM threads
WHERE owner_principal_id = ?
  AND (marked_deleted_at IS NOT NULL OR purged_at IS NOT NULL)`, ownerID)
		if err != nil {
			return fmt.Errorf("query marked threads: %w", err)
		}
		var threadIDs []string
		for threadRows.Next() {
			var tid string
			if err := threadRows.Scan(&tid); err != nil {
				threadRows.Close()
				return err
			}
			threadIDs = append(threadIDs, tid)
		}
		threadRows.Close()

		if len(threadIDs) > 0 {
			// Disable immutability trigger
			if _, err := tx.Exec("UPDATE gc_state SET active = 1 WHERE id = 1"); err != nil {
				return fmt.Errorf("set gc_state active: %w", err)
			}

			for _, tid := range threadIDs {
				if _, err := tx.Exec("DELETE FROM events WHERE thread_id = ?", tid); err != nil {
					return fmt.Errorf("delete events for thread %s: %w", tid, err)
				}
				if _, err := tx.Exec("DELETE FROM threads WHERE id = ?", tid); err != nil {
					return fmt.Errorf("delete thread %s: %w", tid, err)
				}
				stats.PurgedThreads++
			}

			// Re-enable immutability trigger
			if _, err := tx.Exec("UPDATE gc_state SET active = 0 WHERE id = 1"); err != nil {
				return fmt.Errorf("set gc_state inactive: %w", err)
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	// 4. Physical SQLite compaction (outside the transaction)
	var busy, log, checkpointed int
	err = s.db.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &checkpointed)
	if err != nil {
		return nil, fmt.Errorf("deletion committed; compaction failed: wal_checkpoint: %w", err)
	}
	if busy != 0 {
		return nil, fmt.Errorf("deletion committed; compaction failed: wal_checkpoint returned busy=%d", busy)
	}
	if _, err := s.db.Exec("VACUUM"); err != nil {
		return nil, fmt.Errorf("deletion committed; compaction failed: vacuum: %w", err)
	}

	return stats, nil
}

// ListOwnerActors lists all active actors registered under this principal, excluding 'owner'.
func (s *Store) ListOwnerActors(ownerID string) ([]string, error) {
	rows, err := s.db.Query("SELECT actor_label FROM actors WHERE principal_id = ? AND active = 1 AND actor_label != 'owner' ORDER BY actor_label", ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var actors []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		actors = append(actors, a)
	}
	return actors, rows.Err()
}

// MigrateV0Threads assigns all unowned threads (owner_principal_id IS NULL) to ownerID.
func (s *Store) MigrateV0Threads(ownerID string) (int64, error) {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return 0, invalid("owner is required")
	}
	res, err := s.db.Exec("UPDATE threads SET owner_principal_id = ? WHERE owner_principal_id IS NULL", ownerID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
