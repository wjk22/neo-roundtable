package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const pw = "correct horse battery staple"

func TestMain(m *testing.M) {
	// Cheap argon2id parameters; the format carries them per hash.
	Argon2Params.Time, Argon2Params.Memory, Argon2Params.Threads = 1, 8, 1
	m.Run()
}

type env struct {
	t                 *testing.T
	path              string
	s                 *Store
	alice, doc, berry Identity
	now               time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, path: filepath.Join(t.TempDir(), "roundtable.sqlite3"), now: time.Unix(1_800_000_000, 0)}
	e.s = e.open()
	t.Cleanup(func() { e.s.Close() })
	for _, a := range [][2]string{{"admin", "Alice"}, {"admin", "Doc"}, {"berry-owner", "Berry"}} {
		if err := e.s.RegisterActor(a[0], a[1], pw); err != nil {
			t.Fatal(err)
		}
	}
	e.alice, e.doc, e.berry = Identity{"admin", "Alice"}, Identity{"admin", "Doc"}, Identity{"berry-owner", "Berry"}
	return e
}

func (e *env) open() *Store {
	s, err := OpenWithClock(e.path, func() time.Time { return e.now })
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

func (e *env) thread(title string, who ...Identity) string {
	e.t.Helper()
	owner := "admin"
	if len(who) > 0 {
		owner = who[0].PrincipalID
	}
	id, err := e.s.CreateThread(title, owner)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, w := range who {
		if err := e.s.Grant(id, w.ActorLabel); err != nil {
			e.t.Fatal(err)
		}
	}
	return id
}

func sp(s string) *string { return &s }
func ip(i int64) *int64   { return &i }

func (e *env) post(thread string, who Identity, content string) *Event {
	e.t.Helper()
	ev, err := e.s.PostMessage(thread, who, sp(content), nil, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	return ev
}

func TestPrivateByDefaultAndActorLevelListIsolation(t *testing.T) {
	e := newEnv(t)
	id := e.thread("private")
	for _, who := range []Identity{e.alice, e.doc, e.berry} {
		if got, _ := e.s.ListThreads(who); len(got) != 0 {
			t.Fatalf("%v sees ungranted thread", who)
		}
	}
	if err := e.s.Grant(id, "Alice"); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.s.ListThreads(e.alice); len(got) != 1 || got[0].ID != id {
		t.Fatalf("alice list = %v", got)
	}
	// Same principal, different actor: no access.
	if got, _ := e.s.ListThreads(e.doc); len(got) != 0 {
		t.Fatal("same-principal actor leaked")
	}
	if got, _ := e.s.ListThreads(e.berry); len(got) != 0 {
		t.Fatal("other principal leaked")
	}
}

func TestAllowedAndDeniedReadPostIncludingGuessedID(t *testing.T) {
	e := newEnv(t)
	id := e.thread("", e.alice)
	posted := e.post(id, e.alice, "hello")
	if posted.PrincipalID != "admin" || posted.ActorLabel != "Alice" {
		t.Fatalf("provenance = %+v", posted)
	}
	page, err := e.s.GetThread(id, e.alice, 10, nil)
	if err != nil || *page.Events[0].Content != "hello" {
		t.Fatalf("read: %v %v", page, err)
	}
	for _, who := range []Identity{e.doc, e.berry} {
		if _, err := e.s.GetThread(id, who, 10, nil); !errors.Is(err, ErrForbidden) {
			t.Fatalf("read by %v: %v", who, err)
		}
		if _, err := e.s.PostMessage(id, who, sp("intrusion"), nil, nil); !errors.Is(err, ErrForbidden) {
			t.Fatalf("post by %v: %v", who, err)
		}
	}
	if _, err := e.s.GetThread("guessed-thread-id", e.alice, 10, nil); !errors.Is(err, ErrForbidden) {
		t.Fatalf("guessed id: %v", err)
	}
	if n, _ := e.s.EventCount(); n != 1 {
		t.Fatalf("events = %d", n)
	}
}

func TestOrderLimitAndBeforeIDPagination(t *testing.T) {
	e := newEnv(t)
	id := e.thread("", e.alice)
	var ids []int64
	for i := 0; i < 5; i++ {
		ids = append(ids, e.post(id, e.alice, "m").ID)
	}
	first, _ := e.s.GetThread(id, e.alice, 2, nil)
	if first.Events[0].ID != ids[4] || first.Events[1].ID != ids[3] {
		t.Fatalf("first page = %v", first.Events)
	}
	second, _ := e.s.GetThread(id, e.alice, 2, ip(first.Events[1].ID))
	if second.Events[0].ID != ids[2] || second.Events[1].ID != ids[1] {
		t.Fatalf("second page = %v", second.Events)
	}
	for _, bad := range []int{0, -1, 101} {
		if _, err := e.s.GetThread(id, e.alice, bad, nil); !errors.Is(err, ErrInvalid) {
			t.Fatalf("limit %d accepted", bad)
		}
	}
	if _, err := e.s.GetThread(id, e.alice, 10, ip(0)); !errors.Is(err, ErrInvalid) {
		t.Fatal("before_id 0 accepted")
	}
}

func TestReferenceWithoutCopiedTextAndInaccessibleSource(t *testing.T) {
	e := newEnv(t)
	source := e.thread("source", e.alice)
	target := e.thread("target", e.alice, e.doc)
	src := e.post(source, e.alice, "source secret")
	fwd, err := e.s.PostMessage(target, e.alice, sp("context only"), &src.ID, sp("forward"))
	if err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := e.s.DB().QueryRow("SELECT content FROM event_payloads WHERE event_id = ?", fwd.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if raw != "context only" || strings.Contains(raw, "source secret") {
		t.Fatalf("stored content = %q", raw)
	}
	a, _ := e.s.GetThread(target, e.alice, 10, nil)
	if r := a.Events[0].Reference; !r.Accessible || *r.Event.Content != "source secret" {
		t.Fatalf("alice reference = %+v", r)
	}
	d, _ := e.s.GetThread(target, e.doc, 10, nil)
	if r := d.Events[0].Reference; r.Accessible || r.Event != nil || r.EventID != src.ID {
		t.Fatalf("doc reference = %+v", r)
	}
	out, _ := json.Marshal(d)
	if strings.Contains(string(out), "source secret") {
		t.Fatal("source text leaked through reference")
	}
	// A reference cannot be created to an event the poster cannot read.
	if _, err := e.s.PostMessage(target, e.doc, nil, &src.ID, sp("reference")); !errors.Is(err, ErrForbidden) {
		t.Fatalf("doc referenced inaccessible event: %v", err)
	}
}

func TestMalformedPostsAtomicFailuresAndImmutability(t *testing.T) {
	e := newEnv(t)
	id := e.thread("", e.alice)
	bad := []struct {
		content  *string
		ref      *int64
		relation *string
	}{
		{}, {content: sp("")}, {content: sp("   ")},
		{content: sp("x"), relation: sp("forward")},
		{ref: ip(999), relation: sp("forward")},
		{ref: ip(1), relation: sp("invented")},
		{ref: ip(1)},
		{ref: ip(0), relation: sp("forward")},
		{content: sp(strings.Repeat("x", MaxMessage+1))},
	}
	for i, b := range bad {
		if _, err := e.s.PostMessage(id, e.alice, b.content, b.ref, b.relation); err == nil {
			t.Fatalf("bad call %d accepted", i)
		}
	}
	if n, _ := e.s.EventCount(); n != 0 {
		t.Fatalf("failed writes left %d events", n)
	}
	ev := e.post(id, e.alice, "immutable")
	if _, err := e.s.DB().Exec("UPDATE events SET content = 'changed' WHERE id = ?", ev.ID); err == nil {
		t.Fatal("update allowed")
	}
	if _, err := e.s.DB().Exec("DELETE FROM events WHERE id = ?", ev.ID); err == nil {
		t.Fatal("delete allowed")
	}
}

func TestRestartPersistence(t *testing.T) {
	e := newEnv(t)
	id := e.thread("survives", e.alice)
	e.post(id, e.alice, "persisted")
	e.s.Close()
	e.s = e.open()
	list, _ := e.s.ListThreads(e.alice)
	if len(list) != 1 || *list[0].Title != "survives" {
		t.Fatalf("list = %v", list)
	}
	page, _ := e.s.GetThread(id, e.alice, 10, nil)
	if *page.Events[0].Content != "persisted" {
		t.Fatal("event lost")
	}
	if _, ok := e.s.AuthenticateActor("Alice", pw); !ok {
		t.Fatal("actor lost")
	}
}

func TestActorAuthentication(t *testing.T) {
	e := newEnv(t)
	if who, ok := e.s.AuthenticateActor("Alice", pw); !ok || who != e.alice {
		t.Fatal("valid credential rejected")
	}
	if _, ok := e.s.AuthenticateActor("Alice", "wrong password!"); ok {
		t.Fatal("wrong password accepted")
	}
	if _, ok := e.s.AuthenticateActor("Nobody", pw); ok {
		t.Fatal("unknown actor accepted")
	}
	// Each actor has its own password.
	if err := e.s.SetActorPassword("Doc", "another long password"); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.s.AuthenticateActor("Doc", pw); ok {
		t.Fatal("old password still valid")
	}
	if _, ok := e.s.AuthenticateActor("Alice", pw); !ok {
		t.Fatal("rotating Doc affected Alice")
	}
	if err := e.s.RegisterActor("admin", "Alice", pw); !errors.Is(err, ErrInvalid) {
		t.Fatal("duplicate actor label accepted")
	}
	if err := e.s.RegisterActor("admin", "Short", "short"); !errors.Is(err, ErrInvalid) {
		t.Fatal("short password accepted")
	}
	// Passwords are stored only as argon2id hashes.
	var h string
	e.s.DB().QueryRow("SELECT password_hash FROM actors WHERE actor_label = 'Alice'").Scan(&h)
	if !strings.HasPrefix(h, "argon2id$") || strings.Contains(h, pw) {
		t.Fatalf("hash = %q", h)
	}
}

func issue(t *testing.T, e *env, who Identity) (access, refresh string) {
	t.Helper()
	access, refresh = NewToken(), NewToken()
	g := Grant{ClientID: "c", Resource: "https://x/mcp", Identity: who}
	if err := e.s.PutTokens(g, access, refresh); err != nil {
		t.Fatal(err)
	}
	return
}

func TestDeactivateAndRotateRevokeOnlyThatActor(t *testing.T) {
	e := newEnv(t)
	aAcc, aRef := issue(t, e, e.alice)
	dAcc, dRef := issue(t, e, e.doc)
	if _, _, ok := e.s.AccessIdentity(aAcc, "https://x/mcp"); !ok {
		t.Fatal("token not valid before revocation")
	}
	if err := e.s.DeactivateActor("Alice"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := e.s.AccessIdentity(aAcc, "https://x/mcp"); ok {
		t.Fatal("deactivated actor's access token valid")
	}
	if _, ok := e.s.ConsumeRefresh(aRef, "c"); ok {
		t.Fatal("deactivated actor's refresh token valid")
	}
	if err := e.s.PutTokens(Grant{ClientID: "c", Resource: "https://x/mcp", Identity: e.alice}, "a", "b"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("tokens issued to inactive actor: %v", err)
	}
	if _, _, ok := e.s.AccessIdentity(dAcc, "https://x/mcp"); !ok {
		t.Fatal("Doc's token was affected")
	}
	if err := e.s.SetActorPassword("Doc", "rotated password!!"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := e.s.AccessIdentity(dAcc, "https://x/mcp"); ok {
		t.Fatal("rotated actor's access token valid")
	}
	if _, ok := e.s.ConsumeRefresh(dRef, "c"); ok {
		t.Fatal("rotated actor's refresh token valid")
	}
}

func TestAccessTokenAudienceAndExpiry(t *testing.T) {
	e := newEnv(t)
	acc, _ := issue(t, e, e.alice)
	if _, _, ok := e.s.AccessIdentity(acc, "https://other/mcp"); ok {
		t.Fatal("wrong audience accepted")
	}
	e.now = e.now.Add(AccessTokenTTL*time.Second + time.Second)
	if _, _, ok := e.s.AccessIdentity(acc, "https://x/mcp"); ok {
		t.Fatal("expired token accepted")
	}
}

func count(t *testing.T, e *env, table string) (n int) {
	t.Helper()
	if err := e.s.DB().QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return
}

func TestExpiredCodesAndTokensAreRemoved(t *testing.T) {
	e := newEnv(t)
	g := Grant{ClientID: "c", RedirectURI: "r", CodeChallenge: "x", Resource: "https://x/mcp", Identity: e.alice}
	if err := e.s.PutCode("code-1", g); err != nil {
		t.Fatal(err)
	}
	issue(t, e, e.alice)
	if count(t, e, "oauth_codes") != 1 || count(t, e, "oauth_tokens") != 2 {
		t.Fatal("setup rows missing")
	}

	// Removed opportunistically on insert: access tokens and codes expire,
	// the 30-day refresh token does not.
	e.now = e.now.Add(2 * time.Hour)
	if err := e.s.PutCode("code-2", g); err != nil {
		t.Fatal(err)
	}
	if count(t, e, "oauth_codes") != 1 || count(t, e, "oauth_tokens") != 1 {
		t.Fatalf("after insert purge: codes=%d tokens=%d", count(t, e, "oauth_codes"), count(t, e, "oauth_tokens"))
	}
	if _, ok := e.s.ConsumeCode("code-1"); ok {
		t.Fatal("expired code consumable")
	}
	e.now = e.now.Add(RefreshTokenTTL*time.Second + time.Hour)
	issue(t, e, e.alice)
	if n := count(t, e, "oauth_tokens"); n != 2 {
		t.Fatalf("expired tokens not purged on insert: %d", n)
	}

	// And at startup.
	e.now = e.now.Add(2 * RefreshTokenTTL * time.Second)
	e.s.Close()
	e.s = e.open()
	if count(t, e, "oauth_codes") != 0 || count(t, e, "oauth_tokens") != 0 {
		t.Fatal("startup did not purge expired state")
	}
}

func TestCodeIsSingleUseAndCapped(t *testing.T) {
	e := newEnv(t)
	g := Grant{ClientID: "c", RedirectURI: "r", CodeChallenge: "x", Resource: "https://x/mcp", Identity: e.alice}
	if err := e.s.PutCode("once", g); err != nil {
		t.Fatal(err)
	}
	if got, ok := e.s.ConsumeCode("once"); !ok || got.Identity != e.alice {
		t.Fatal("first consume failed")
	}
	if _, ok := e.s.ConsumeCode("once"); ok {
		t.Fatal("code reused")
	}
	for i := 0; i < MaxPendingCodes; i++ {
		if err := e.s.PutCode(NewToken(), g); err != nil {
			t.Fatalf("code %d: %v", i, err)
		}
	}
	if err := e.s.PutCode(NewToken(), g); !errors.Is(err, ErrBusy) {
		t.Fatalf("cap not enforced: %v", err)
	}
	e.now = e.now.Add(CodeTTL*time.Second + time.Second)
	if err := e.s.PutCode(NewToken(), g); err != nil {
		t.Fatalf("expired codes should free capacity: %v", err)
	}
}

func TestOwnerAuthentication(t *testing.T) {
	e := newEnv(t)
	if err := e.s.SetOwnerPassword("admin", "too-short"); err == nil {
		t.Fatal("expected error on short password")
	}
	if err := e.s.SetOwnerPassword("admin", pw); err != nil {
		t.Fatal(err)
	}
	ok, err := e.s.AuthenticateOwner("admin", pw)
	if err != nil || !ok {
		t.Fatalf("auth failed: ok=%v, err=%v", ok, err)
	}
	ok, err = e.s.AuthenticateOwner("admin", "wrong-password-123")
	if err != nil || ok {
		t.Fatalf("auth should fail: ok=%v, err=%v", ok, err)
	}
	ok, err = e.s.AuthenticateOwner("unknown-user", pw)
	if err != nil || ok {
		t.Fatalf("unknown user auth should fail: ok=%v, err=%v", ok, err)
	}
}

func TestOwnerSessions(t *testing.T) {
	e := newEnv(t)
	if err := e.s.SetOwnerPassword("admin", pw); err != nil {
		t.Fatal(err)
	}

	secret, err := e.s.CreateOwnerSession("admin", 3600)
	if err != nil {
		t.Fatal(err)
	}

	// Verify raw secret is NOT in database, only its hash
	var count int
	e.s.db.QueryRow("SELECT count(*) FROM owner_sessions WHERE session_hash = ?", secret).Scan(&count)
	if count > 0 {
		t.Fatal("raw session secret was stored directly in database!")
	}

	user, ok := e.s.ValidateOwnerSession(secret)
	if !ok || user != "admin" {
		t.Fatalf("session validation failed: user=%q, ok=%v", user, ok)
	}

	// Password rotation revokes active sessions
	if err := e.s.SetOwnerPassword("admin", "new-password-1234"); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.s.ValidateOwnerSession(secret); ok {
		t.Fatal("session should be revoked after password rotation")
	}

	// Expiry and purge
	secret2, err := e.s.CreateOwnerSession("admin", 10)
	if err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(20 * time.Second)
	if _, ok := e.s.ValidateOwnerSession(secret2); ok {
		t.Fatal("expired session should not be valid")
	}
	if err := e.s.PurgeExpired(); err != nil {
		t.Fatal(err)
	}
	e.s.db.QueryRow("SELECT count(*) FROM owner_sessions").Scan(&count)
	if count != 0 {
		t.Fatalf("expired session not purged, remaining: %d", count)
	}
}

func TestOwnerReservedLabel(t *testing.T) {
	e := newEnv(t)
	if err := e.s.RegisterActor("admin", "owner", pw); err == nil {
		t.Fatal("expected error registering reserved label 'owner'")
	}
	if err := e.s.RegisterActor("admin", "OWNER", pw); err == nil {
		t.Fatal("expected error registering case-insensitive reserved label 'OWNER'")
	}
}

func TestOwnerThreadsAndTombstoning(t *testing.T) {
	e := newEnv(t)
	// Create thread owned by admin
	tid, err := e.s.CreateThread("v1-thread", "admin")
	if err != nil {
		t.Fatal(err)
	}

	// Grant Alice
	if err := e.s.GrantOwnerActor(tid, "admin", "Alice"); err != nil {
		t.Fatal(err)
	}

	// Post message as human owner
	msg, err := e.s.PostOwnerMessage(tid, "admin", "Hello from owner")
	if err != nil {
		t.Fatal(err)
	}
	if msg.ActorLabel != "owner" || msg.PrincipalID != "admin" {
		t.Fatalf("unexpected provenance: %+v", msg)
	}

	// Alice reads it via MCP GetThread
	page, err := e.s.GetThread(tid, e.alice, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 1 || page.Events[0].ActorLabel != "owner" {
		t.Fatalf("Alice could not read owner message: %+v", page.Events)
	}

	// Owner reads it via GetOwnerThread
	ownerPage, err := e.s.GetOwnerThread(tid, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if len(ownerPage.Events) != 1 || ownerPage.Thread.TombstonedAt != nil {
		t.Fatalf("unexpected owner page: %+v", ownerPage)
	}

	// Tombstone thread
	if err := e.s.TombstoneThread(tid, "admin"); err != nil {
		t.Fatal(err)
	}

	// Idempotent second tombstone
	if err := e.s.TombstoneThread(tid, "admin"); err != nil {
		t.Fatalf("idempotent tombstone should not fail: %v", err)
	}

	// Verify only ONE tombstone event was appended
	var tombstoneEvents int
	e.s.db.QueryRow("SELECT count(*) FROM events WHERE thread_id = ? AND event_kind = 'thread_tombstoned'", tid).
		Scan(&tombstoneEvents)
	if tombstoneEvents != 1 {
		t.Fatalf("expected exactly 1 tombstone event, got %d", tombstoneEvents)
	}

	// Owner can still read thread audit history
	ownerAudit, err := e.s.GetOwnerThread(tid, "admin")
	if err != nil {
		t.Fatalf("owner should be able to audit tombstoned thread: %v", err)
	}
	if ownerAudit.Thread.TombstonedAt == nil {
		t.Fatal("tombstoned_at was not recorded on thread")
	}
	if len(ownerAudit.Events) != 2 { // human message + tombstone event
		t.Fatalf("expected 2 events in audit log, got %d", len(ownerAudit.Events))
	}

	// AI actor access is cut off
	threads, err := e.s.ListThreads(e.alice)
	if err != nil {
		t.Fatal(err)
	}
	for _, th := range threads {
		if th.ID == tid {
			t.Fatal("tombstoned thread should not appear in Alice's ListThreads")
		}
	}
	if _, err := e.s.GetThread(tid, e.alice, 10, nil); !errors.Is(err, ErrForbidden) {
		t.Fatalf("Alice GetThread should return ErrForbidden, got %v", err)
	}
	if _, err := e.s.PostMessage(tid, e.alice, sp("new message"), nil, nil); !errors.Is(err, ErrForbidden) {
		t.Fatalf("Alice PostMessage should return ErrForbidden, got %v", err)
	}
}

func TestTombstoneClosesAllWritePaths(t *testing.T) {
	e := newEnv(t)
	tid, err := e.s.CreateThread("write-close-test", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.s.Grant(tid, "Alice"); err != nil {
		t.Fatal(err)
	}
	if err := e.s.TombstoneThread(tid, "admin"); err != nil {
		t.Fatal(err)
	}

	// 1. PostOwnerMessage
	if _, err := e.s.PostOwnerMessage(tid, "admin", "test"); err == nil {
		t.Fatal("PostOwnerMessage on tombstoned thread should fail")
	}
	// 2. GrantOwnerActor
	if err := e.s.GrantOwnerActor(tid, "admin", "Doc"); err == nil {
		t.Fatal("GrantOwnerActor on tombstoned thread should fail")
	}
	// 3. RevokeOwnerActor
	if err := e.s.RevokeOwnerActor(tid, "admin", "Alice"); err == nil {
		t.Fatal("RevokeOwnerActor on tombstoned thread should fail")
	}
	// 4. CLI / store Grant
	if err := e.s.Grant(tid, "Doc"); err == nil {
		t.Fatal("Grant on tombstoned thread should fail")
	}
	// 5. CLI / store Revoke
	if err := e.s.Revoke(tid, "Alice"); err == nil {
		t.Fatal("Revoke on tombstoned thread should fail")
	}
	// 6. MCP PostMessage
	if _, err := e.s.PostMessage(tid, e.alice, sp("hello"), nil, nil); !errors.Is(err, ErrForbidden) {
		t.Fatalf("MCP PostMessage should return ErrForbidden on tombstoned thread, got %v", err)
	}
}

func TestCrossPrincipalActorGrantForbidden(t *testing.T) {
	e := newEnv(t)
	// Thread owned by admin
	tid, err := e.s.CreateThread("isolation-test", "admin")
	if err != nil {
		t.Fatal(err)
	}
	// Attempt to grant Berry (registered under berry-owner)
	if err := e.s.Grant(tid, "Berry"); err == nil {
		t.Fatal("expected error granting actor belonging to a different principal")
	}
	if err := e.s.GrantOwnerActor(tid, "admin", "Berry"); err == nil {
		t.Fatal("expected error GrantOwnerActor for actor belonging to a different principal")
	}
}

func TestTombstoneReferenceMasking(t *testing.T) {
	e := newEnv(t)
	t1 := e.thread("t1", e.alice)
	t2 := e.thread("t2", e.alice)

	ev1 := e.post(t1, e.alice, "source event in t1")
	rel := "reference"
	ev2, err := e.s.PostMessage(t2, e.alice, nil, &ev1.ID, &rel)
	if err != nil {
		t.Fatal(err)
	}
	if ev2.Reference == nil || !ev2.Reference.Accessible {
		t.Fatal("reference should be accessible initially")
	}

	// Tombstone t1
	if err := e.s.TombstoneThread(t1, "admin"); err != nil {
		t.Fatal(err)
	}

	// Reading t2: reference to t1 must now be masked (accessible: false)
	page, err := e.s.GetThread(t2, e.alice, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) == 0 || page.Events[0].Reference == nil || page.Events[0].Reference.Accessible {
		t.Fatalf("reference to tombstoned thread should be masked as inaccessible: %+v", page.Events[0])
	}
}

func TestMigrateV0Threads(t *testing.T) {
	e := newEnv(t)
	// Insert raw thread without owner_principal_id simulating V0 state
	_, err := e.s.db.Exec("INSERT INTO threads (id, title, created_at, owner_principal_id) VALUES ('v0-orphan', 'old', ?, NULL)", e.s.stamp())
	if err != nil {
		t.Fatal(err)
	}

	n, err := e.s.MigrateV0Threads("admin")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 migrated thread, got %d", n)
	}

	// Repeat migration should find 0 threads
	n, err = e.s.MigrateV0Threads("admin")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("expected 0 migrated threads on repeat, got %d", n)
	}

	var owner string
	e.s.db.QueryRow("SELECT owner_principal_id FROM threads WHERE id = 'v0-orphan'").Scan(&owner)
	if owner != "admin" {
		t.Fatalf("expected owner admin, got %q", owner)
	}
}

func TestMigrationToEventPayloadsAndTriggerIntegrity(t *testing.T) {
	// Test migration from legacy schema with events.content column
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "legacy.db")

	dsn := "file:" + url.PathEscape(dbPath) + "?_txlock=immediate&_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)"
	rawDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}

	legacySchema := `
CREATE TABLE threads (
    id TEXT PRIMARY KEY,
    title TEXT,
    created_at TEXT NOT NULL,
    owner_principal_id TEXT,
    tombstoned_at TEXT
);

CREATE TABLE thread_acl (
    thread_id TEXT NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
    principal_id TEXT NOT NULL,
    actor_label TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (thread_id, principal_id, actor_label)
);

CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id TEXT NOT NULL REFERENCES threads(id),
    created_at TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    actor_label TEXT NOT NULL,
    content TEXT,
    ref_id INTEGER REFERENCES events(id),
    relation TEXT,
    event_kind TEXT NOT NULL DEFAULT 'entry' CHECK (event_kind IN ('entry', 'thread_tombstoned')),
    CHECK (
        (ref_id IS NULL AND relation IS NULL AND content IS NOT NULL)
        OR
        (ref_id IS NOT NULL AND relation IS NOT NULL)
    )
);

CREATE TRIGGER events_no_update
BEFORE UPDATE ON events BEGIN
    SELECT RAISE(ABORT, 'events are immutable');
END;

CREATE TRIGGER events_no_delete
BEFORE DELETE ON events BEGIN
    SELECT RAISE(ABORT, 'events are immutable');
END;
`
	if _, err := rawDB.Exec(legacySchema); err != nil {
		t.Fatal(err)
	}

	// Insert legacy threads and events
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := rawDB.Exec("INSERT INTO threads (id, title, created_at, owner_principal_id) VALUES ('t1', 'Legacy Thread', ?, 'admin')", now); err != nil {
		t.Fatal(err)
	}
	if _, err := rawDB.Exec("INSERT INTO thread_acl (thread_id, principal_id, actor_label, created_at) VALUES ('t1', 'admin', 'alice', ?)", now); err != nil {
		t.Fatal(err)
	}
	if _, err := rawDB.Exec("INSERT INTO events (id, thread_id, created_at, principal_id, actor_label, content, ref_id, relation, event_kind) VALUES (1, 't1', ?, 'admin', 'alice', 'legacy msg 1', NULL, NULL, 'entry')", now); err != nil {
		t.Fatal(err)
	}
	if _, err := rawDB.Exec("INSERT INTO events (id, thread_id, created_at, principal_id, actor_label, content, ref_id, relation, event_kind) VALUES (2, 't1', ?, 'admin', 'alice', 'legacy fwd note', 1, 'reference', 'entry')", now); err != nil {
		t.Fatal(err)
	}
	rawDB.Close()

	// Open with Store.Open (executing migration)
	st, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open migrated db failed: %v", err)
	}
	defer st.Close()

	// Verify events still have IDs 1 and 2
	who := Identity{PrincipalID: "admin", ActorLabel: "alice"}
	page, err := st.GetThread("t1", who, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(page.Events))
	}
	// Descending order: event 2 then event 1
	if page.Events[0].ID != 2 || *page.Events[0].Content != "legacy fwd note" {
		t.Fatalf("unexpected event 2: %+v", page.Events[0])
	}
	if page.Events[0].Reference == nil || !page.Events[0].Reference.Accessible || *page.Events[0].Reference.Event.Content != "legacy msg 1" {
		t.Fatalf("unexpected reference in event 2: %+v", page.Events[0].Reference)
	}
	if page.Events[1].ID != 1 || *page.Events[1].Content != "legacy msg 1" {
		t.Fatalf("unexpected event 1: %+v", page.Events[1])
	}

	// Verify events table triggers are intact
	if _, err := st.db.Exec("UPDATE events SET actor_label = 'hacked' WHERE id = 1"); err == nil {
		t.Fatal("expected events_no_update trigger to block update")
	}
	if _, err := st.db.Exec("DELETE FROM events WHERE id = 1"); err == nil {
		t.Fatal("expected events_no_delete trigger to block delete")
	}
}

func TestMarkMessageAndImmediateMasking(t *testing.T) {
	e := newEnv(t)
	tid := e.thread("m-thread", e.alice)
	msg := e.post(tid, e.alice, "sensitive message")

	// Verify initial content visible
	page, err := e.s.GetThread(tid, e.alice, 10, nil)
	if err != nil || *page.Events[0].Content != "sensitive message" {
		t.Fatalf("initial message content unexpected: %+v", page)
	}

	// Owner marks message for deletion
	if err := e.s.MarkMessageDeleted(tid, "admin", msg.ID); err != nil {
		t.Fatal(err)
	}

	// Repeated mark is idempotent
	if err := e.s.MarkMessageDeleted(tid, "admin", msg.ID); err != nil {
		t.Fatal(err)
	}

	// Non-owner cannot mark message
	if err := e.s.MarkMessageDeleted(tid, "stranger", msg.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden for stranger, got %v", err)
	}

	// Actor MCP view: content immediately masked as [Marked for deletion]
	page, err = e.s.GetThread(tid, e.alice, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if *page.Events[0].Content != "[Marked for deletion]" || !page.Events[0].MarkedDeleted {
		t.Fatalf("actor view should show [Marked for deletion]: %+v", page.Events[0])
	}

	// Owner view: content immediately masked as [Marked for deletion]
	opage, err := e.s.GetOwnerThread(tid, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if *opage.Events[0].Content != "[Marked for deletion]" || !opage.Events[0].MarkedDeleted {
		t.Fatalf("owner view should show [Marked for deletion]: %+v", opage.Events[0])
	}

	// Reference from another thread immediately resolves to masked placeholder
	t2 := e.thread("t2", e.alice)
	fwd, err := e.s.PostMessage(t2, e.alice, sp("note"), &msg.ID, sp("reference"))
	if err != nil {
		t.Fatal(err)
	}
	if fwd.Reference == nil || !fwd.Reference.Accessible || *fwd.Reference.Event.Content != "[Marked for deletion]" {
		t.Fatalf("reference to marked event should be masked: %+v", fwd.Reference)
	}
}

func TestMarkThreadClosesAllPaths(t *testing.T) {
	e := newEnv(t)
	tid := e.thread("close-me", e.alice)
	e.post(tid, e.alice, "thread content")

	// Owner marks thread for deletion
	if err := e.s.MarkThreadDeleted(tid, "admin"); err != nil {
		t.Fatal(err)
	}

	// Idempotent repeat
	if err := e.s.MarkThreadDeleted(tid, "admin"); err != nil {
		t.Fatal(err)
	}

	// Actor MCP calls: GetThread -> ErrForbidden
	if _, err := e.s.GetThread(tid, e.alice, 10, nil); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden for actor GetThread on marked thread, got %v", err)
	}

	// Actor MCP calls: PostMessage -> ErrForbidden
	if _, err := e.s.PostMessage(tid, e.alice, sp("new post"), nil, nil); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden for actor PostMessage on marked thread, got %v", err)
	}

	// Actor MCP calls: ListThreads -> thread omitted
	threads, err := e.s.ListThreads(e.alice)
	if err != nil {
		t.Fatal(err)
	}
	for _, th := range threads {
		if th.ID == tid {
			t.Fatalf("marked thread %s should not appear in ListThreads", tid)
		}
	}

	// Web owner mutations fail
	if _, err := e.s.PostOwnerMessage(tid, "admin", "owner post"); err == nil {
		t.Fatal("expected PostOwnerMessage to fail on marked thread")
	}
	if err := e.s.GrantOwnerActor(tid, "admin", "alice"); err == nil {
		t.Fatal("expected GrantOwnerActor to fail on marked thread")
	}
	if err := e.s.RevokeOwnerActor(tid, "admin", "alice"); err == nil {
		t.Fatal("expected RevokeOwnerActor to fail on marked thread")
	}
	if err := e.s.TombstoneThread(tid, "admin"); err == nil {
		t.Fatal("expected TombstoneThread to fail on marked thread")
	}

	// Owner view shows marked status and masked payloads
	opage, err := e.s.GetOwnerThread(tid, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if opage.Thread.MarkedDeletedAt == nil {
		t.Fatal("expected MarkedDeletedAt to be set")
	}
	if *opage.Events[0].Content != "[Marked for deletion]" || !opage.Events[0].MarkedDeleted {
		t.Fatalf("expected masked content for event in marked thread: %+v", opage.Events[0])
	}

	// Also test marking an already tombstoned thread
	t2 := e.thread("tomb-then-mark", e.alice)
	if err := e.s.TombstoneThread(t2, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := e.s.MarkThreadDeleted(t2, "admin"); err != nil {
		t.Fatal(err)
	}
	opage2, err := e.s.GetOwnerThread(t2, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if opage2.Thread.TombstonedAt == nil || opage2.Thread.MarkedDeletedAt == nil {
		t.Fatalf("expected both tombstoned and marked to be set: %+v", opage2.Thread)
	}
}

func TestGarbageCollectionPermanentErasureAndStubs(t *testing.T) {
	e := newEnv(t)
	t1 := e.thread("thread-1", e.alice)
	m1 := e.post(t1, e.alice, "keeper message")
	m2 := e.post(t1, e.alice, "delete-me message")

	t2 := e.thread("thread-2", e.alice)
	fwd, err := e.s.PostMessage(t2, e.alice, sp("fwd note"), &m2.ID, sp("reference"))
	if err != nil {
		t.Fatal(err)
	}

	t3 := e.thread("thread-3", e.alice)
	m4 := e.post(t3, e.alice, "thread-3 payload")

	// Mark m2 for deletion
	if err := e.s.MarkMessageDeleted(t1, "admin", m2.ID); err != nil {
		t.Fatal(err)
	}
	// Mark t3 for deletion
	if err := e.s.MarkThreadDeleted(t3, "admin"); err != nil {
		t.Fatal(err)
	}

	// Check GC counts
	counts, err := e.s.GetGCCounts("admin")
	if err != nil {
		t.Fatal(err)
	}
	if counts.MarkedMessages != 1 || counts.MarkedThreads != 1 {
		t.Fatalf("expected 1 marked message and 1 marked thread, got %+v", counts)
	}

	// Run GarbageCollect
	stats, err := e.s.GarbageCollect("admin")
	if err != nil {
		t.Fatal(err)
	}
	if stats.PurgedMessages != 1 || stats.PurgedThreads != 1 {
		t.Fatalf("expected 1 purged message and 1 purged thread, got %+v", stats)
	}

	// Verify m2 and m4 payloads are gone from event_payloads
	var count int
	e.s.db.QueryRow("SELECT count(*) FROM event_payloads WHERE event_id IN (?, ?)", m2.ID, m4.ID).Scan(&count)
	if count != 0 {
		t.Fatalf("expected 0 payloads for purged events, got %d", count)
	}

	// Verify m1 payload is still in event_payloads
	var m1Content string
	if err := e.s.db.QueryRow("SELECT content FROM event_payloads WHERE event_id = ?", m1.ID).Scan(&m1Content); err != nil || m1Content != "keeper message" {
		t.Fatalf("expected keeper message to survive, got %q, err %v", m1Content, err)
	}

	// Verify event stub STILL EXISTS for m2, but NOT for m4 (entire thread purged)
	var stubCount int
	e.s.db.QueryRow("SELECT count(*) FROM events WHERE id = ?", m2.ID).Scan(&stubCount)
	if stubCount != 1 {
		t.Fatalf("expected 1 event stub for m2 in events table, got %d", stubCount)
	}
	e.s.db.QueryRow("SELECT count(*) FROM events WHERE id = ?", m4.ID).Scan(&stubCount)
	if stubCount != 0 {
		t.Fatalf("expected 0 event stubs for m4 in events table, got %d", stubCount)
	}

	// Thread 1: m2 now renders [Purged]
	page1, err := e.s.GetThread(t1, e.alice, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range page1.Events {
		if ev.ID == m2.ID {
			if *ev.Content != "[Purged]" || !ev.Purged {
				t.Fatalf("expected [Purged] content for m2, got %+v", ev)
			}
		}
	}

	// Thread 2: reference to m2 resolves cleanly as [Purged] without FK crash
	page2, err := e.s.GetThread(t2, e.alice, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(page2.Events) == 0 || page2.Events[0].ID != fwd.ID {
		t.Fatalf("unexpected page 2 events: %+v", page2)
	}
	if ref := page2.Events[0].Reference; !ref.Accessible || *ref.Event.Content != "[Purged]" {
		t.Fatalf("expected reference to show [Purged], got %+v", ref)
	}

	// Thread 3: thread and all associated data should be completely deleted
	_, err = e.s.GetOwnerThread(t3, "admin")
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden for completely deleted thread 3, got %v", err)
	}

	var tCount int
	e.s.db.QueryRow("SELECT count(*) FROM threads WHERE id = ?", t3).Scan(&tCount)
	if tCount != 0 {
		t.Fatalf("expected 0 rows in threads for t3, got %d", tCount)
	}

	// Repeated GC is idempotent
	stats2, err := e.s.GarbageCollect("admin")
	if err != nil {
		t.Fatal(err)
	}
	if stats2.PurgedMessages != 0 || stats2.PurgedThreads != 0 {
		t.Fatalf("repeated GC should purge 0, got %+v", stats2)
	}
}

func TestActorGrantRevokeLifecycle(t *testing.T) {
	e := newEnv(t)
	bob := Identity{PrincipalID: "admin", ActorLabel: "bob"}
	if err := e.s.RegisterActor("admin", "bob", pw); err != nil {
		t.Fatal(err)
	}

	tid := e.thread("acl-test", e.alice)

	// Alice has access, Bob does not
	if _, err := e.s.GetThread(tid, e.alice, 10, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.GetThread(tid, bob, 10, nil); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden for bob, got %v", err)
	}

	// Revoke Alice
	if err := e.s.RevokeOwnerActor(tid, "admin", e.alice.ActorLabel); err != nil {
		t.Fatal(err)
	}
	// Alice immediately blocked
	if _, err := e.s.GetThread(tid, e.alice, 10, nil); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden for revoked alice, got %v", err)
	}

	// Grant Bob
	if err := e.s.GrantOwnerActor(tid, "admin", "bob"); err != nil {
		t.Fatal(err)
	}
	// Bob now has access
	if _, err := e.s.GetThread(tid, bob, 10, nil); err != nil {
		t.Fatalf("bob should have access: %v", err)
	}
}
