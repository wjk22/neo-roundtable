// Package store is the SQLite persistence and authorization layer.
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	_ "modernc.org/sqlite"
)

const (
	MaxPage          = 100
	MaxMessage       = 32768
	MaxReferenceNote = 1000
)

var (
	// ErrForbidden means the actor cannot access a thread or event. Callers
	// must not reveal whether the target exists.
	ErrForbidden = errors.New("thread or event not found or access denied")
	// ErrInvalid marks malformed caller input.
	ErrInvalid = errors.New("invalid input")
	// ErrBusy means a bounded resource is full.
	ErrBusy = errors.New("too many pending items")
)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Identity is the server-derived principal/actor pair.
type Identity struct {
	PrincipalID string
	ActorLabel  string
}

type Store struct {
	db *sql.DB
	// Now is the clock; tests replace it.
	Now func() time.Time
}

const schema = `
CREATE TABLE IF NOT EXISTS threads (
    id TEXT PRIMARY KEY,
    title TEXT,
    created_at TEXT NOT NULL,
    owner_principal_id TEXT,
    tombstoned_at TEXT,
    marked_deleted_at TEXT,
    purged_at TEXT
);

CREATE TABLE IF NOT EXISTS thread_acl (
    thread_id TEXT NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
    principal_id TEXT NOT NULL,
    actor_label TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (thread_id, principal_id, actor_label)
);

CREATE TABLE IF NOT EXISTS gc_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    active INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO gc_state (id, active) VALUES (1, 0);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id TEXT NOT NULL REFERENCES threads(id),
    created_at TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    actor_label TEXT NOT NULL,
    ref_id INTEGER,
    relation TEXT,
    event_kind TEXT NOT NULL DEFAULT 'entry' CHECK (event_kind IN ('entry', 'thread_tombstoned')),
    CHECK (
        (ref_id IS NULL AND relation IS NULL)
        OR
        (ref_id IS NOT NULL AND relation IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS event_payloads (
    event_id INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
    content TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS event_deletions (
    event_id INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
    marked_at TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS events_no_update
BEFORE UPDATE ON events BEGIN
    SELECT RAISE(ABORT, 'events are immutable');
END;

CREATE TRIGGER IF NOT EXISTS events_no_delete
BEFORE DELETE ON events
WHEN (SELECT active FROM gc_state WHERE id = 1) = 0
BEGIN
    SELECT RAISE(ABORT, 'events are immutable');
END;

-- Authentication and OAuth operational state; not conversation-domain tables.
-- Each actor has its own password. actor_label is globally unique so the
-- authorize page can identify an actor by label alone.
CREATE TABLE IF NOT EXISTS actors (
    actor_label TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_codes (
    code_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    resource TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    actor_label TEXT NOT NULL REFERENCES actors(actor_label),
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_tokens (
    token_hash TEXT PRIMARY KEY,
    token_type TEXT NOT NULL CHECK (token_type IN ('access', 'refresh')),
    client_id TEXT NOT NULL,
    resource TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    actor_label TEXT NOT NULL REFERENCES actors(actor_label),
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS owner_credentials (
    principal_id TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS owner_sessions (
    session_hash TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
`

func (s *Store) migrate() error {
	hasCol := func(table, col string) (bool, error) {
		rows, err := s.db.Query("PRAGMA table_info(" + table + ")")
		if err != nil {
			return false, err
		}
		defer rows.Close()
		for rows.Next() {
			var cid int
			var name, ctype string
			var notnull, pk int
			var dflt any
			if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
				return false, err
			}
			if name == col {
				return true, nil
			}
		}
		return false, rows.Err()
	}

	hasOwner, err := hasCol("threads", "owner_principal_id")
	if err != nil {
		return err
	}
	if !hasOwner {
		if _, err := s.db.Exec("ALTER TABLE threads ADD COLUMN owner_principal_id TEXT"); err != nil {
			return fmt.Errorf("migrate threads owner_principal_id: %w", err)
		}
	}

	hasTombstone, err := hasCol("threads", "tombstoned_at")
	if err != nil {
		return err
	}
	if !hasTombstone {
		if _, err := s.db.Exec("ALTER TABLE threads ADD COLUMN tombstoned_at TEXT"); err != nil {
			return fmt.Errorf("migrate threads tombstoned_at: %w", err)
		}
	}

	hasMarkedDeleted, err := hasCol("threads", "marked_deleted_at")
	if err != nil {
		return err
	}
	if !hasMarkedDeleted {
		if _, err := s.db.Exec("ALTER TABLE threads ADD COLUMN marked_deleted_at TEXT"); err != nil {
			return fmt.Errorf("migrate threads marked_deleted_at: %w", err)
		}
	}

	hasPurged, err := hasCol("threads", "purged_at")
	if err != nil {
		return err
	}
	if !hasPurged {
		if _, err := s.db.Exec("ALTER TABLE threads ADD COLUMN purged_at TEXT"); err != nil {
			return fmt.Errorf("migrate threads purged_at: %w", err)
		}
	}

	hasKind, err := hasCol("events", "event_kind")
	if err != nil {
		return err
	}
	if !hasKind {
		if _, err := s.db.Exec("ALTER TABLE events ADD COLUMN event_kind TEXT NOT NULL DEFAULT 'entry' CHECK (event_kind IN ('entry', 'thread_tombstoned'))"); err != nil {
			return fmt.Errorf("migrate events event_kind: %w", err)
		}
	}

	payloadAndDeletionsTables := `
CREATE TABLE IF NOT EXISTS event_payloads (
    event_id INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
    content TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS event_deletions (
    event_id INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
    marked_at TEXT NOT NULL
);
`
	if _, err := s.db.Exec(payloadAndDeletionsTables); err != nil {
		return fmt.Errorf("migrate event_payloads and event_deletions tables: %w", err)
	}

	// Check if legacy events table still has the content column.
	// If so, migrate existing non-null content to event_payloads and rebuild events.
	hasContent, err := hasCol("events", "content")
	if err != nil {
		return err
	}
	if hasContent {
		if _, err := s.db.Exec("INSERT OR IGNORE INTO event_payloads (event_id, content) SELECT id, content FROM events WHERE content IS NOT NULL"); err != nil {
			return fmt.Errorf("migrate copy content to event_payloads: %w", err)
		}

		rebuildScript := `
PRAGMA foreign_keys = OFF;

CREATE TABLE events_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id TEXT NOT NULL REFERENCES threads(id),
    created_at TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    actor_label TEXT NOT NULL,
    ref_id INTEGER,
    relation TEXT,
    event_kind TEXT NOT NULL DEFAULT 'entry' CHECK (event_kind IN ('entry', 'thread_tombstoned')),
    CHECK (
        (ref_id IS NULL AND relation IS NULL)
        OR
        (ref_id IS NOT NULL AND relation IS NOT NULL)
    )
);

INSERT INTO events_new (id, thread_id, created_at, principal_id, actor_label, ref_id, relation, event_kind)
SELECT id, thread_id, created_at, principal_id, actor_label, ref_id, relation, event_kind FROM events;

DROP TRIGGER IF EXISTS events_no_update;
DROP TRIGGER IF EXISTS events_no_delete;

DROP TABLE events;

ALTER TABLE events_new RENAME TO events;

CREATE TRIGGER IF NOT EXISTS events_no_update
BEFORE UPDATE ON events BEGIN
    SELECT RAISE(ABORT, 'events are immutable');
END;

CREATE TRIGGER IF NOT EXISTS events_no_delete
BEFORE DELETE ON events
WHEN (SELECT active FROM gc_state WHERE id = 1) = 0
BEGIN
    SELECT RAISE(ABORT, 'events are immutable');
END;

PRAGMA foreign_keys = ON;
`
		if _, err := s.db.Exec(rebuildScript); err != nil {
			return fmt.Errorf("rebuild events table: %w", err)
		}

		fkRows, err := s.db.Query("PRAGMA foreign_key_check")
		if err != nil {
			return fmt.Errorf("foreign_key_check query: %w", err)
		}
		defer fkRows.Close()
		if fkRows.Next() {
			return errors.New("foreign key check failed after rebuilding events table")
		}
	}

	ownerTables := `
CREATE TABLE IF NOT EXISTS owner_credentials (
    principal_id TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS owner_sessions (
    session_hash TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
`
	if _, err := s.db.Exec(ownerTables); err != nil {
		return fmt.Errorf("migrate owner tables: %w", err)
	}
	needsGCRebuild := false
	fkRows, err := s.db.Query("PRAGMA foreign_key_list('events')")
	if err != nil {
		return err
	}
	defer fkRows.Close()
	for fkRows.Next() {
		var id, seq int
		var table, from, to, onUpdate, onDelete, match string
		if err := fkRows.Scan(&id, &seq, &table, &from, &to, &onUpdate, &onDelete, &match); err != nil {
			return err
		}
		if table == "events" {
			needsGCRebuild = true
		}
	}

	if needsGCRebuild {
		// Rebuild events table to remove ref_id foreign key
		rebuildGCScript := `
PRAGMA foreign_keys = OFF;

CREATE TABLE events_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id TEXT NOT NULL REFERENCES threads(id),
    created_at TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    actor_label TEXT NOT NULL,
    ref_id INTEGER,
    relation TEXT,
    event_kind TEXT NOT NULL DEFAULT 'entry' CHECK (event_kind IN ('entry', 'thread_tombstoned')),
    CHECK (
        (ref_id IS NULL AND relation IS NULL)
        OR
        (ref_id IS NOT NULL AND relation IS NOT NULL)
    )
);

INSERT INTO events_new (id, thread_id, created_at, principal_id, actor_label, ref_id, relation, event_kind)
SELECT id, thread_id, created_at, principal_id, actor_label, ref_id, relation, event_kind FROM events;

DROP TRIGGER IF EXISTS events_no_update;
DROP TRIGGER IF EXISTS events_no_delete;

DROP TABLE events;

ALTER TABLE events_new RENAME TO events;

CREATE TRIGGER IF NOT EXISTS events_no_update
BEFORE UPDATE ON events BEGIN
    SELECT RAISE(ABORT, 'events are immutable');
END;

CREATE TRIGGER IF NOT EXISTS events_no_delete
BEFORE DELETE ON events
WHEN (SELECT active FROM gc_state WHERE id = 1) = 0
BEGIN
    SELECT RAISE(ABORT, 'events are immutable');
END;

PRAGMA foreign_keys = ON;
`
		if _, err := s.db.Exec(rebuildGCScript); err != nil {
			return fmt.Errorf("rebuild events table for gc: %w", err)
		}

		fkCheckRows, err := s.db.Query("PRAGMA foreign_key_check")
		if err != nil {
			return fmt.Errorf("foreign_key_check query after gc migrate: %w", err)
		}
		defer fkCheckRows.Close()
		if fkCheckRows.Next() {
			return errors.New("foreign key check failed after rebuilding events table for gc")
		}
	} else {
		// Even if we don't need to rebuild the table, we MUST ensure the trigger has the gc_state check
		var triggerSQL string
		err = s.db.QueryRow("SELECT sql FROM sqlite_master WHERE type='trigger' AND name='events_no_delete'").Scan(&triggerSQL)
		if err == nil && !strings.Contains(triggerSQL, "gc_state") {
			updateTriggerScript := `
	DROP TRIGGER IF EXISTS events_no_delete;
	CREATE TRIGGER events_no_delete
	BEFORE DELETE ON events
	WHEN (SELECT active FROM gc_state WHERE id = 1) = 0
	BEGIN
		SELECT RAISE(ABORT, 'events are immutable');
	END;
	`
			if _, err := s.db.Exec(updateTriggerScript); err != nil {
				return fmt.Errorf("update events_no_delete trigger: %w", err)
			}
		}
	}

	return nil
}

// Open opens (creating and migrating if needed) the SQLite database at path
// and removes expired OAuth state.
func Open(path string) (*Store, error) { return OpenWithClock(path, time.Now) }

// OpenWithClock is Open with an injected clock (tests).
func OpenWithClock(path string, now func() time.Time) (*Store, error) {
	dsn := "file:" + url.PathEscape(path) +
		"?_txlock=immediate&_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=secure_delete(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, Now: now}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize schema: %w", err)
	}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate schema: %w", err)
	}
	if err := s.PurgeExpired(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// DB exposes the handle for tests that must probe raw persisted state.
func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) stamp() string {
	return s.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Store) tx(fn func(*sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

type queryer interface {
	QueryRow(query string, args ...any) *sql.Row
}

func authorized(q queryer, threadID string, who Identity) bool {
	var one int
	err := q.QueryRow(
		"SELECT 1 FROM thread_acl a JOIN threads t ON t.id = a.thread_id "+
			"WHERE a.thread_id = ? AND a.principal_id = ? AND a.actor_label = ? "+
			"AND t.tombstoned_at IS NULL AND t.marked_deleted_at IS NULL AND t.purged_at IS NULL",
		threadID, who.PrincipalID, who.ActorLabel).Scan(&one)
	return err == nil
}

// CreateThread creates a private thread with no ACL entries.
func (s *Store) CreateThread(title, ownerPrincipalID string) (string, error) {
	title = strings.TrimSpace(title)
	if utf8.RuneCountInString(title) > 200 {
		return "", invalid("title is too long")
	}
	ownerPrincipalID = strings.TrimSpace(ownerPrincipalID)
	if ownerPrincipalID == "" {
		return "", invalid("owner principal is required")
	}
	var t any
	if title != "" {
		t = title
	}
	b := make([]byte, 18)
	rand.Read(b)
	id := base64.RawURLEncoding.EncodeToString(b)
	_, err := s.db.Exec("INSERT INTO threads (id, title, created_at, owner_principal_id) VALUES (?, ?, ?, ?)",
		id, t, s.stamp(), ownerPrincipalID)
	return id, err
}

// Grant gives a registered, active actor access to a thread. The principal is
// taken from the actor registration.
func (s *Store) Grant(threadID, actorLabel string) error {
	return s.tx(func(tx *sql.Tx) error {
		var tombstonedAt, markedDeletedAt, purgedAt sql.NullString
		var ownerPrincipal sql.NullString
		err := tx.QueryRow("SELECT tombstoned_at, marked_deleted_at, purged_at, owner_principal_id FROM threads WHERE id = ?", threadID).
			Scan(&tombstonedAt, &markedDeletedAt, &purgedAt, &ownerPrincipal)
		if err != nil {
			return invalid("thread is missing")
		}
		if tombstonedAt.Valid {
			return invalid("thread is tombstoned")
		}
		if markedDeletedAt.Valid {
			return invalid("thread is marked for deletion")
		}
		if purgedAt.Valid {
			return invalid("thread is purged")
		}
		var principal string
		err = tx.QueryRow("SELECT principal_id FROM actors WHERE actor_label = ? AND active = 1",
			actorLabel).Scan(&principal)
		if err != nil {
			return invalid("actor is not registered")
		}
		if ownerPrincipal.Valid && ownerPrincipal.String != principal {
			return invalid("actor does not belong to thread owner")
		}
		if _, err := tx.Exec("INSERT INTO thread_acl (thread_id, principal_id, actor_label, created_at) VALUES (?, ?, ?, ?)",
			threadID, principal, actorLabel, s.stamp()); err != nil {
			return invalid("grant already exists")
		}
		return nil
	})
}

// Revoke removes an actor's access to a thread.
func (s *Store) Revoke(threadID, actorLabel string) error {
	return s.tx(func(tx *sql.Tx) error {
		var tombstonedAt, markedDeletedAt, purgedAt sql.NullString
		err := tx.QueryRow("SELECT tombstoned_at, marked_deleted_at, purged_at FROM threads WHERE id = ?", threadID).
			Scan(&tombstonedAt, &markedDeletedAt, &purgedAt)
		if err != nil {
			return invalid("thread is missing")
		}
		if tombstonedAt.Valid {
			return invalid("thread is tombstoned")
		}
		if markedDeletedAt.Valid {
			return invalid("thread is marked for deletion")
		}
		if purgedAt.Valid {
			return invalid("thread is purged")
		}
		res, err := tx.Exec("DELETE FROM thread_acl WHERE thread_id = ? AND actor_label = ?",
			threadID, actorLabel)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return invalid("grant does not exist")
		}
		return nil
	})
}

type Thread struct {
	ID        string  `json:"id"`
	Title     *string `json:"title"`
	CreatedAt string  `json:"created_at"`
}

// ListThreads returns only threads granted to the exact principal/actor pair.
func (s *Store) ListThreads(who Identity) ([]Thread, error) {
	rows, err := s.db.Query(
		"SELECT t.id, t.title, t.created_at FROM threads t "+
			"JOIN thread_acl a ON a.thread_id = t.id "+
			"WHERE a.principal_id = ? AND a.actor_label = ? "+
			"AND t.tombstoned_at IS NULL AND t.marked_deleted_at IS NULL AND t.purged_at IS NULL "+
			"ORDER BY t.created_at, t.id",
		who.PrincipalID, who.ActorLabel)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Thread{}
	for rows.Next() {
		var t Thread
		if err := rows.Scan(&t.ID, &t.Title, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

type EventSummary struct {
	ID            int64   `json:"id"`
	ThreadID      string  `json:"thread_id"`
	CreatedAt     string  `json:"created_at"`
	PrincipalID   string  `json:"principal_id"`
	ActorLabel    string  `json:"actor_label"`
	Content       *string `json:"content"`
	EventKind     string  `json:"event_kind"`
	MarkedDeleted bool    `json:"marked_deleted,omitempty"`
	Purged        bool    `json:"purged,omitempty"`
}

type Reference struct {
	EventID    int64         `json:"event_id"`
	Accessible bool          `json:"accessible"`
	Event      *EventSummary `json:"event,omitempty"`
}

type Event struct {
	EventSummary
	Relation  *string    `json:"relation,omitempty"`
	RefID     *int64     `json:"ref_id,omitempty"`
	Reference *Reference `json:"reference,omitempty"`
}

type ThreadPage struct {
	Thread Thread  `json:"thread"`
	Events []Event `json:"events"`
}

const eventSelect = `
SELECT e.id, e.thread_id, e.created_at, e.principal_id, e.actor_label,
       e.ref_id, e.relation, e.event_kind,
       p.content,
       d.marked_at,
       t.marked_deleted_at, t.purged_at
FROM events e
JOIN threads t ON e.thread_id = t.id
LEFT JOIN event_payloads p ON p.event_id = e.id
LEFT JOIN event_deletions d ON d.event_id = e.id
`

func scanEvent(r interface{ Scan(...any) error }) (Event, error) {
	var e Event
	var refID sql.NullInt64
	var relation sql.NullString
	var rawContent sql.NullString
	var markedAt sql.NullString
	var threadMarked sql.NullString
	var threadPurged sql.NullString

	err := r.Scan(
		&e.ID, &e.ThreadID, &e.CreatedAt, &e.PrincipalID, &e.ActorLabel,
		&refID, &relation, &e.EventKind,
		&rawContent,
		&markedAt,
		&threadMarked, &threadPurged,
	)
	if err != nil {
		return e, err
	}
	if refID.Valid {
		e.RefID = &refID.Int64
	}
	if relation.Valid {
		e.Relation = &relation.String
	}

	marked := markedAt.Valid || threadMarked.Valid
	purged := threadPurged.Valid || (marked && !rawContent.Valid)

	if purged {
		e.Purged = true
		s := "[Purged]"
		e.Content = &s
	} else if marked {
		e.MarkedDeleted = true
		s := "[Marked for deletion]"
		e.Content = &s
	} else if rawContent.Valid {
		e.Content = &rawContent.String
	} else {
		e.Content = nil
	}
	return e, nil
}

// render attaches reference information. A reference reveals the source event
// only when the reader is independently authorized for the source thread.
func render(q queryer, e Event, who Identity) (Event, error) {
	if e.RefID == nil {
		return e, nil
	}
	ref := &Reference{EventID: *e.RefID}
	src, err := scanEvent(q.QueryRow(eventSelect+" WHERE e.id = ?", *e.RefID))
	if err == nil && authorized(q, src.ThreadID, who) {
		ref.Accessible = true
		summary := src.EventSummary
		ref.Event = &summary
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return e, err
	}
	e.Reference = ref
	return e, nil
}

// GetThread returns a newest-first page of an authorized thread.
func (s *Store) GetThread(threadID string, who Identity, limit int, beforeID *int64) (*ThreadPage, error) {
	if limit < 1 || limit > MaxPage {
		return nil, invalid("limit must be an integer from 1 to %d", MaxPage)
	}
	if beforeID != nil && *beforeID < 1 {
		return nil, invalid("before_id must be a positive integer or null")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if !authorized(tx, threadID, who) {
		return nil, ErrForbidden
	}
	page := &ThreadPage{Events: []Event{}}
	if err := tx.QueryRow("SELECT id, title, created_at FROM threads WHERE id = ?", threadID).
		Scan(&page.Thread.ID, &page.Thread.Title, &page.Thread.CreatedAt); err != nil {
		return nil, err
	}
	query := eventSelect + " WHERE e.thread_id = ?"
	args := []any{threadID}
	if beforeID != nil {
		query += " AND e.id < ?"
		args = append(args, *beforeID)
	}
	query += " ORDER BY e.id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, err
	}
	var raw []Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		raw = append(raw, e)
	}
	rows.Close()
	for _, e := range raw {
		e, err := render(tx, e, who)
		if err != nil {
			return nil, err
		}
		page.Events = append(page.Events, e)
	}
	return page, nil
}

// PostMessage appends one immutable event. Normal messages carry content and
// no ref_id/relation; reference events carry ref_id, a relation and an
// optional short note.
func (s *Store) PostMessage(threadID string, who Identity, content *string, refID *int64, relation *string) (*Event, error) {
	if refID == nil {
		if relation != nil || content == nil || strings.TrimSpace(*content) == "" {
			return nil, invalid("normal messages require non-empty content and no ref_id/relation")
		}
		if utf8.RuneCountInString(*content) > MaxMessage {
			return nil, invalid("message content is too long")
		}
	} else {
		if *refID < 1 {
			return nil, invalid("ref_id must be a positive integer or null")
		}
		if relation == nil || (*relation != "reference" && *relation != "forward") {
			return nil, invalid("reference messages require relation 'reference' or 'forward'")
		}
		if content != nil && utf8.RuneCountInString(*content) > MaxReferenceNote {
			return nil, invalid("reference note is too long")
		}
	}
	var posted *Event
	err := s.tx(func(tx *sql.Tx) error {
		if !authorized(tx, threadID, who) {
			return ErrForbidden
		}
		if refID != nil {
			var srcThread string
			err := tx.QueryRow("SELECT thread_id FROM events WHERE id = ?", *refID).Scan(&srcThread)
			if err != nil || !authorized(tx, srcThread, who) {
				return ErrForbidden
			}
		}
		res, err := tx.Exec(
			"INSERT INTO events (thread_id, created_at, principal_id, actor_label, ref_id, relation, event_kind) "+
				"VALUES (?, ?, ?, ?, ?, ?, 'entry')",
			threadID, s.stamp(), who.PrincipalID, who.ActorLabel, refID, relation)
		if err != nil {
			return err
		}
		id, _ := res.LastInsertId()
		if content != nil && strings.TrimSpace(*content) != "" {
			if _, err := tx.Exec("INSERT INTO event_payloads (event_id, content) VALUES (?, ?)", id, *content); err != nil {
				return err
			}
		}
		e, err := scanEvent(tx.QueryRow(eventSelect+" WHERE e.id = ?", id))
		if err != nil {
			return err
		}
		e, err = render(tx, e, who)
		posted = &e
		return err
	})
	if err != nil {
		return nil, err
	}
	return posted, nil
}

func (s *Store) EventCount() (n int, err error) {
	err = s.db.QueryRow("SELECT count(*) FROM events").Scan(&n)
	return
}
