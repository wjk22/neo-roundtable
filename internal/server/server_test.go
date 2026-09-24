package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/wjk22/neo-roundtable/internal/store"
)

const (
	public   = "https://roundtable.example"
	redirect = "https://client.example/callback"
	chatgpt  = "https://chatgpt.com/connector/oauth/abc123"
	pass     = "correct horse battery staple"
	verifier = "v-0123456789012345678901234567890123456789012345"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type env struct {
	t    *testing.T
	path string
	key  []byte
	now  time.Time
	logs *syncBuf
	st   *store.Store
	srv  *Server
	ts   *httptest.Server
	http *http.Client
}

func newEnv(t *testing.T) *env {
	t.Helper()
	store.Argon2Params.Time, store.Argon2Params.Memory, store.Argon2Params.Threads = 1, 8, 1
	e := &env{
		t: t, path: filepath.Join(t.TempDir(), "rt.db"), now: time.Unix(1_800_000_000, 0),
		key:  bytes.Repeat([]byte{7}, 32),
		logs: &syncBuf{},
		http: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
	e.start()
	for _, a := range [][2]string{{"admin", "Alice"}, {"admin", "Doc"}, {"berry-owner", "Berry"}} {
		if err := e.st.RegisterActor(a[0], a[1], pass); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(e.stop)
	return e
}

func (e *env) start() {
	st, err := store.OpenWithClock(e.path, func() time.Time { return e.now })
	if err != nil {
		e.t.Fatal(err)
	}
	srv, err := New(Config{
		Store: st, PublicURL: public, SigningKey: e.key,
		Redirects: []string{redirect, "https://chatgpt.com/connector/oauth/*"},
		Logger:    slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now:       func() time.Time { return e.now },
	})
	if err != nil {
		e.t.Fatal(err)
	}
	e.st, e.srv, e.ts = st, srv, httptest.NewServer(srv.Handler())
}

func (e *env) stop() {
	e.ts.Close()
	e.st.Close()
}

func (e *env) restart() {
	e.stop()
	e.start()
}

func (e *env) do(method, path string, form url.Values, header http.Header) (*http.Response, []byte) {
	e.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, e.ts.URL+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := e.http.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func (e *env) register(uris ...string) (string, *http.Response, []byte) {
	e.t.Helper()
	raw, _ := json.Marshal(map[string]any{"redirect_uris": uris, "token_endpoint_auth_method": "none"})
	req, _ := http.NewRequest("POST", e.ts.URL+"/oauth/register", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.http.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var out struct {
		ClientID string `json:"client_id"`
	}
	json.Unmarshal(b, &out)
	return out.ClientID, resp, b
}

func challenge(v string) string { return pkceS256(v) }

func authzForm(clientID, actor, password string) url.Values {
	return url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect},
		"state": {"st-1"}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"},
		"resource": {public + "/mcp"}, "actor": {actor}, "password": {password},
	}
}

func (e *env) authorize(clientID, actor, password string) (*http.Response, []byte) {
	return e.do("POST", "/oauth/authorize", authzForm(clientID, actor, password), nil)
}

func codeFrom(t *testing.T, resp *http.Response) string {
	t.Helper()
	if resp.StatusCode != 302 {
		t.Fatalf("authorize status = %d", resp.StatusCode)
	}
	u, _ := url.Parse(resp.Header.Get("Location"))
	if u.Query().Get("state") != "st-1" {
		t.Fatalf("state not echoed: %s", u)
	}
	return u.Query().Get("code")
}

type tokens struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
}

func (e *env) exchange(clientID, code string) (*http.Response, []byte) {
	return e.do("POST", "/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code},
		"redirect_uri": {redirect}, "code_verifier": {verifier}, "resource": {public + "/mcp"},
	}, nil)
}

// login runs register -> authorize -> token for one actor.
func (e *env) login(actor string) tokens {
	e.t.Helper()
	id, _, _ := e.register(redirect)
	resp, _ := e.authorize(id, actor, pass)
	code := codeFrom(e.t, resp)
	resp, body := e.exchange(id, code)
	if resp.StatusCode != 200 {
		e.t.Fatalf("token: %d %s", resp.StatusCode, body)
	}
	var tk tokens
	json.Unmarshal(body, &tk)
	return tk
}

type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

func (e *env) session(token string) *mcp.ClientSession {
	e.t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	cs, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:   e.ts.URL + "/mcp",
		HTTPClient: &http.Client{Transport: bearer{token}},
	}, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (map[string]any, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return nil, true
	}
	if res.IsError {
		return nil, true
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Content[0].(*mcp.TextContent).Text), &out); err != nil {
		t.Fatal(err)
	}
	return out, false
}

func (e *env) thread(actors ...string) string {
	e.t.Helper()
	id, err := e.st.CreateThread("t", "admin")
	if err != nil {
		e.t.Fatal(err)
	}
	for _, a := range actors {
		if err := e.st.Grant(id, a); err != nil {
			e.t.Fatal(err)
		}
	}
	return id
}

func (e *env) mcpStatus(token string) int {
	req, _ := http.NewRequest("POST", e.ts.URL+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_threads","arguments":{}}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := e.http.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// ---- end to end ----

func TestEndToEndOAuthAndMCPRoundtrip(t *testing.T) {
	e := newEnv(t)
	thread := e.thread("Alice")
	tk := e.login("Alice")
	cs := e.session(tk.Access)

	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range tools.Tools {
		names = append(names, tl.Name)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "get_thread,list_threads,post_message" {
		t.Fatalf("tool surface = %v", names)
	}

	list, isErr := call(t, cs, "list_threads", nil)
	if isErr || list["threads"].([]any)[0].(map[string]any)["id"] != thread {
		t.Fatalf("list = %v", list)
	}
	posted, isErr := call(t, cs, "post_message", map[string]any{"thread_id": thread, "content": "hello"})
	if isErr || posted["actor_label"] != "Alice" || posted["principal_id"] != "admin" {
		t.Fatalf("post = %v", posted)
	}
	page, isErr := call(t, cs, "get_thread", map[string]any{"thread_id": thread})
	if isErr || page["events"].([]any)[0].(map[string]any)["content"] != "hello" {
		t.Fatalf("get = %v", page)
	}

	// Restart keeps the token grant and the data.
	e.restart()
	cs = e.session(tk.Access)
	if page, isErr = call(t, cs, "get_thread", map[string]any{"thread_id": thread}); isErr {
		t.Fatal("token or thread lost across restart")
	}
}

func TestUnauthenticatedMCPAndNoPerActorRoutes(t *testing.T) {
	e := newEnv(t)
	req, _ := http.NewRequest("POST", e.ts.URL+"/mcp", strings.NewReader("{}"))
	resp, _ := e.http.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"),
		public+"/.well-known/oauth-protected-resource/mcp") {
		t.Fatalf("no token: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	req, _ = http.NewRequest("POST", e.ts.URL+"/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer nonsense")
	resp, _ = e.http.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("bad token: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	tk := e.login("Alice")
	for _, path := range []string{"/a/anything/mcp", "/mcp/", "/a/Alice/mcp"} {
		req, _ := http.NewRequest("POST", e.ts.URL+path, strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+tk.Access)
		resp, _ := e.http.Do(req)
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Fatalf("%s served: %d", path, resp.StatusCode)
		}
	}
}

func TestMetadataIsFixedAndIgnoresHostHeaders(t *testing.T) {
	e := newEnv(t)
	h := http.Header{"X-Forwarded-Host": {"evil.example"}}
	req, _ := http.NewRequest("GET", e.ts.URL+"/.well-known/oauth-protected-resource", nil)
	req.Host = "evil.example"
	req.Header = h
	resp, _ := e.http.Do(req)
	var meta map[string]any
	json.NewDecoder(resp.Body).Decode(&meta)
	resp.Body.Close()
	if meta["resource"] != public+"/mcp" || meta["authorization_servers"].([]any)[0] != public {
		t.Fatalf("resource metadata = %v", meta)
	}
	_, body := e.do("GET", "/.well-known/oauth-authorization-server", nil, h)
	var as map[string]any
	json.Unmarshal(body, &as)
	if as["issuer"] != public || as["authorization_endpoint"] != public+"/oauth/authorize" ||
		as["registration_endpoint"] != public+"/oauth/register" {
		t.Fatalf("AS metadata = %v", as)
	}
	if resp, _ := e.do("GET", "/.well-known/openid-configuration", nil, nil); resp.StatusCode != 404 {
		t.Fatal("openid-configuration served")
	}
}

// ---- actor selection at authorize time ----

func TestAuthorizePageHeaders(t *testing.T) {
	e := newEnv(t)
	id, _, _ := e.register(redirect)
	q := authzForm(id, "", "")
	q.Del("actor")
	q.Del("password")
	resp, body := e.do("GET", "/oauth/authorize?"+q.Encode(), nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	csp := resp.Header.Get("Content-Security-Policy")
	for _, want := range []string{"frame-ancestors 'none'", "default-src 'none'", "style-src 'unsafe-inline'", "form-action 'self'"} {
		if !strings.Contains(csp, want) {
			t.Fatalf("CSP %q lacks %q", csp, want)
		}
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", resp.Header.Get("Cache-Control"))
	}
	if !strings.Contains(string(body), `name="actor"`) || !strings.Contains(string(body), `name="password"`) {
		t.Fatal("form lacks actor/password fields")
	}
	// A failed login page carries the same headers.
	resp, _ = e.authorize(id, "Alice", "wrong password!")
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("error page lacks frame-ancestors")
	}
}

func TestWrongPasswordAndUnknownActorAreIndistinguishable(t *testing.T) {
	e := newEnv(t)
	id, _, _ := e.register(redirect)
	wrong, wrongBody := e.authorize(id, "Alice", "not the password")
	unknown, unknownBody := e.authorize(id, "Nobody", pass)
	if wrong.StatusCode != 401 || unknown.StatusCode != 401 {
		t.Fatalf("statuses %d %d", wrong.StatusCode, unknown.StatusCode)
	}
	if wrong.Header.Get("Location") != "" || unknown.Header.Get("Location") != "" {
		t.Fatal("denied authorize redirected")
	}
	// Bodies differ only in nothing: hidden fields are identical for both.
	strip := func(b []byte) string { return strings.ReplaceAll(string(b), "Nobody", "Alice") }
	if strip(wrongBody) != strip(unknownBody) {
		t.Fatalf("response shapes differ:\n%s\n%s", wrongBody, unknownBody)
	}
	// Deactivated actors look the same too.
	if err := e.st.DeactivateActor("Doc"); err != nil {
		t.Fatal(err)
	}
	inactive, _ := e.authorize(id, "Doc", pass)
	if inactive.StatusCode != 401 {
		t.Fatalf("inactive actor status %d", inactive.StatusCode)
	}
}

func TestTwoActorsOfOnePrincipalGetIsolatedTokens(t *testing.T) {
	e := newEnv(t)
	forAlice, forDoc := e.thread("Alice"), e.thread("Doc")
	alice, doc := e.login("Alice"), e.login("Doc")
	sa, sd := e.session(alice.Access), e.session(doc.Access)

	if l, _ := call(t, sa, "list_threads", nil); len(l["threads"].([]any)) != 1 ||
		l["threads"].([]any)[0].(map[string]any)["id"] != forAlice {
		t.Fatalf("alice list = %v", l)
	}
	if l, _ := call(t, sd, "list_threads", nil); len(l["threads"].([]any)) != 1 ||
		l["threads"].([]any)[0].(map[string]any)["id"] != forDoc {
		t.Fatalf("doc list = %v", l)
	}
	if _, isErr := call(t, sd, "get_thread", map[string]any{"thread_id": forAlice}); !isErr {
		t.Fatal("doc read alice's thread")
	}
	if _, isErr := call(t, sd, "post_message", map[string]any{"thread_id": forAlice, "content": "x"}); !isErr {
		t.Fatal("doc posted to alice's thread")
	}
	if _, isErr := call(t, sa, "get_thread", map[string]any{"thread_id": forDoc}); !isErr {
		t.Fatal("alice read doc's thread")
	}
	if n, _ := e.st.EventCount(); n != 0 {
		t.Fatalf("events = %d", n)
	}
	// Authorship comes from each token's own actor.
	ev, _ := call(t, sd, "post_message", map[string]any{"thread_id": forDoc, "content": "from doc"})
	if ev["actor_label"] != "Doc" {
		t.Fatalf("author = %v", ev["actor_label"])
	}
}

func TestCallerSuppliedIdentityCannotOverride(t *testing.T) {
	e := newEnv(t)
	thread := e.thread("Alice")
	cs := e.session(e.login("Doc").Access)
	for _, args := range []map[string]any{
		{"thread_id": thread, "content": "spoof", "principal_id": "admin", "actor_label": "Alice"},
		{"thread_id": thread, "content": "spoof", "actor": "Alice"},
	} {
		if _, isErr := call(t, cs, "post_message", args); !isErr {
			t.Fatalf("spoofed call accepted: %v", args)
		}
	}
	if _, isErr := call(t, cs, "get_thread", map[string]any{"thread_id": thread}); !isErr {
		t.Fatal("doc read alice's thread")
	}
	if n, _ := e.st.EventCount(); n != 0 {
		t.Fatalf("events = %d", n)
	}
	// User-Agent and client name do not matter either: same token, same actor.
	req, _ := http.NewRequest("POST", e.ts.URL+"/mcp", strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"post_message","arguments":{"thread_id":"`+thread+`","content":"x"}}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("User-Agent", "Alice")
	req.Header.Set("X-Actor", "Alice")
	req.Header.Set("Authorization", "Bearer "+e.login("Doc").Access)
	resp, _ := e.http.Do(req)
	resp.Body.Close()
	if n, _ := e.st.EventCount(); n != 0 {
		t.Fatal("header spoof wrote an event")
	}
}

func TestDeactivateAndRotateInvalidateTokens(t *testing.T) {
	e := newEnv(t)
	alice, doc := e.login("Alice"), e.login("Doc")
	if e.mcpStatus(alice.Access) != 200 || e.mcpStatus(doc.Access) != 200 {
		t.Fatal("tokens not valid before revocation")
	}
	if err := e.st.DeactivateActor("Alice"); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetActorPassword("Doc", "a brand new password"); err != nil {
		t.Fatal(err)
	}
	if e.mcpStatus(alice.Access) != 401 || e.mcpStatus(doc.Access) != 401 {
		t.Fatal("revoked access tokens still valid")
	}
	id, _, _ := e.register(redirect)
	for _, tk := range []tokens{alice, doc} {
		resp, _ := e.do("POST", "/oauth/token", url.Values{
			"grant_type": {"refresh_token"}, "client_id": {id}, "refresh_token": {tk.Refresh}}, nil)
		if resp.StatusCode != 400 {
			t.Fatalf("revoked refresh token accepted: %d", resp.StatusCode)
		}
	}
	// The old password no longer authenticates Doc; the new one does.
	if resp, _ := e.authorize(id, "Doc", pass); resp.StatusCode != 401 {
		t.Fatal("old password accepted")
	}
	resp, _ := e.do("POST", "/oauth/authorize", authzForm(id, "Doc", "a brand new password"), nil)
	if resp.StatusCode != 302 {
		t.Fatalf("new password rejected: %d", resp.StatusCode)
	}
}

// ---- token endpoint ----

func TestCodeAndRefreshRules(t *testing.T) {
	e := newEnv(t)
	id, _, _ := e.register(redirect)
	code := codeFrom(t, must(e.authorize(id, "Alice", pass)))
	if resp, _ := e.exchange(id, code); resp.StatusCode != 200 {
		t.Fatal("first exchange failed")
	}
	if resp, body := e.exchange(id, code); resp.StatusCode != 400 || !strings.Contains(string(body), "invalid_grant") {
		t.Fatalf("code reuse: %d %s", resp.StatusCode, body)
	}

	tryExchange := func(mutate func(url.Values)) int {
		code := codeFrom(t, must(e.authorize(id, "Alice", pass)))
		f := url.Values{"grant_type": {"authorization_code"}, "client_id": {id}, "code": {code},
			"redirect_uri": {redirect}, "code_verifier": {verifier}}
		mutate(f)
		resp, _ := e.do("POST", "/oauth/token", f, nil)
		return resp.StatusCode
	}
	if s := tryExchange(func(f url.Values) { f.Set("code_verifier", strings.Repeat("x", 50)) }); s != 400 {
		t.Fatalf("wrong verifier: %d", s)
	}
	if s := tryExchange(func(f url.Values) { f.Set("redirect_uri", chatgpt) }); s != 400 {
		t.Fatalf("wrong redirect: %d", s)
	}
	other, _, _ := e.register(redirect, chatgpt)
	if s := tryExchange(func(f url.Values) { f.Set("client_id", other) }); s != 400 {
		t.Fatalf("wrong client: %d", s)
	}
	if s := tryExchange(func(f url.Values) { f.Set("resource", public+"/a/x/mcp") }); s != 400 {
		t.Fatalf("wrong resource: %d", s)
	}

	// Refresh rotates: new pair issued, old refresh token rejected.
	tk := e.login("Alice")
	form := func(rt string) url.Values {
		return url.Values{"grant_type": {"refresh_token"}, "client_id": {id}, "refresh_token": {rt}}
	}
	_ = tk
	c2 := codeFrom(t, must(e.authorize(id, "Alice", pass)))
	_, body := e.exchange(id, c2)
	var pair tokens
	json.Unmarshal(body, &pair)
	resp, body := e.do("POST", "/oauth/token", form(pair.Refresh), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("refresh: %d %s", resp.StatusCode, body)
	}
	var next tokens
	json.Unmarshal(body, &next)
	if next.Access == pair.Access || next.Refresh == pair.Refresh || e.mcpStatus(next.Access) != 200 {
		t.Fatal("refresh did not issue a fresh usable pair")
	}
	if resp, _ := e.do("POST", "/oauth/token", form(pair.Refresh), nil); resp.StatusCode != 400 {
		t.Fatal("old refresh token reusable")
	}
}

func must(resp *http.Response, _ []byte) *http.Response { return resp }

func TestFixedAudienceOnly(t *testing.T) {
	e := newEnv(t)
	id, _, _ := e.register(redirect)
	// Authorize with a per-actor style resource is refused, no code issued.
	f := authzForm(id, "Alice", pass)
	f.Set("resource", public+"/a/binding/mcp")
	resp, _ := e.do("POST", "/oauth/authorize", f, nil)
	if resp.StatusCode != 302 || !strings.Contains(resp.Header.Get("Location"), "error=invalid_target") ||
		strings.Contains(resp.Header.Get("Location"), "code=") {
		t.Fatalf("authorize other resource: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	// A token persisted for any other audience is not accepted at /mcp.
	tk := store.NewToken()
	err := e.st.PutTokens(store.Grant{ClientID: id, Resource: public + "/a/binding/mcp",
		Identity: store.Identity{PrincipalID: "admin", ActorLabel: "Alice"}}, tk, store.NewToken())
	if err != nil {
		t.Fatal(err)
	}
	if e.mcpStatus(tk) != 401 {
		t.Fatal("wrong-audience token accepted")
	}
}

func TestExpiredCodeAndTokenAreRejected(t *testing.T) {
	e := newEnv(t)
	id, _, _ := e.register(redirect)
	code := codeFrom(t, must(e.authorize(id, "Alice", pass)))
	e.now = e.now.Add(61 * time.Second)
	if resp, _ := e.exchange(id, code); resp.StatusCode != 400 {
		t.Fatalf("expired code: %d", resp.StatusCode)
	}
	tk := e.login("Alice")
	e.now = e.now.Add(time.Hour + time.Second)
	if e.mcpStatus(tk.Access) != 401 {
		t.Fatal("expired access token accepted")
	}
}

func TestPendingCodeCap(t *testing.T) {
	e := newEnv(t)
	id, _, _ := e.register(redirect)
	g := store.Grant{ClientID: id, RedirectURI: redirect, CodeChallenge: "x", Resource: public + "/mcp",
		Identity: store.Identity{PrincipalID: "admin", ActorLabel: "Alice"}}
	for i := 0; i < store.MaxPendingCodes; i++ {
		if err := e.st.PutCode(store.NewToken(), g); err != nil {
			t.Fatal(err)
		}
	}
	if resp, _ := e.authorize(id, "Alice", pass); resp.StatusCode != 503 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

// ---- stateless registration (H1) ----

func TestRegisterWritesNothingToTheDatabase(t *testing.T) {
	e := newEnv(t)
	snapshot := func() map[string]int {
		out := map[string]int{}
		rows, err := e.st.DB().Query("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
		if err != nil {
			t.Fatal(err)
		}
		var tables []string
		for rows.Next() {
			var n string
			rows.Scan(&n)
			tables = append(tables, n)
		}
		rows.Close()
		for _, n := range tables {
			var c int
			e.st.DB().QueryRow("SELECT count(*) FROM " + n).Scan(&c)
			out[n] = c
		}
		return out
	}
	before := snapshot()
	for i := 0; i < 3; i++ {
		if id, resp, _ := e.register(redirect); resp.StatusCode != 201 || id == "" {
			t.Fatal("registration failed")
		}
	}
	after := snapshot()
	for k, v := range before {
		if after[k] != v {
			t.Fatalf("table %s changed: %d -> %d", k, v, after[k])
		}
	}
	// Stronger: registration works with a closed database.
	closed, err := store.Open(filepath.Join(t.TempDir(), "closed.db"))
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	srv, _ := New(Config{Store: closed, PublicURL: public, SigningKey: e.key, Redirects: []string{redirect}})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	resp, err := http.Post(ts.URL+"/oauth/register", "application/json",
		strings.NewReader(`{"redirect_uris":["`+redirect+`"]}`))
	if err != nil || resp.StatusCode != 201 {
		t.Fatalf("register with closed db: %v %v", resp, err)
	}
	resp.Body.Close()
}

func TestTamperedClientIDsAreRejected(t *testing.T) {
	e := newEnv(t)
	id, _, _ := e.register(redirect)
	parts := strings.Split(id, ".")
	forgedPayload, _ := signClientID(bytes.Repeat([]byte{9}, 32), clientPayload{[]string{redirect}, "none", 1})
	swapped, _ := signClientID(e.key, clientPayload{[]string{chatgpt}, "none", 1})
	flip := parts[1][:len(parts[1])-2] + "AA"
	for name, bad := range map[string]string{
		"payload swapped under old signature": strings.Split(swapped, ".")[0] + "." + parts[1],
		"signature altered":                   parts[0] + "." + flip,
		"signed by another key":               forgedPayload,
		"no signature":                        parts[0],
		"garbage":                             "not-a-client-id",
	} {
		resp, _ := e.authorize(bad, "Alice", pass)
		if resp.StatusCode != 400 || resp.Header.Get("Location") != "" {
			t.Fatalf("%s: authorize %d %q", name, resp.StatusCode, resp.Header.Get("Location"))
		}
		resp, _ = e.exchange(bad, "whatever")
		if resp.StatusCode != 401 {
			t.Fatalf("%s: token %d", name, resp.StatusCode)
		}
	}
}

func TestRedirectWildcardMatchesOnlyAsPrefix(t *testing.T) {
	e := newEnv(t)
	for _, ok := range []string{chatgpt, "https://chatgpt.com/connector/oauth/", redirect} {
		if _, resp, body := e.register(ok); resp.StatusCode != 201 {
			t.Fatalf("%s rejected: %s", ok, body)
		}
	}
	for _, bad := range []string{
		"https://chatgpt.com/connector/oauth",
		"https://chatgpt.com/connector/oauthx",
		"https://chatgpt.com/connector",
		"https://chatgpt.com.evil.example/connector/oauth/x",
		"https://evil.example/?u=https://chatgpt.com/connector/oauth/x",
		"http://chatgpt.com/connector/oauth/x",
		"https://chatgpt.com/connector/oauth/x#frag",
		"https://user@chatgpt.com/connector/oauth/x",
		"https://client.example/callback/",
		"https://client.example/callback?x=1",
		"https://client.example/*",
	} {
		if _, resp, _ := e.register(bad); resp.StatusCode != 400 {
			t.Fatalf("%s accepted", bad)
		}
	}
	if _, resp, _ := e.register(redirect, "https://evil.example/"); resp.StatusCode != 400 {
		t.Fatal("mixed list with one bad URI accepted")
	}
	for _, bad := range []string{"https://a.example/*/b", "https://a.example/*x*", "http://a.example/x", "*"} {
		if ValidateAllowlist([]string{bad}) == nil {
			t.Fatalf("allowlist entry %q accepted", bad)
		}
	}
	// Authorize and token enforce the same rules against the signed client.
	id, _, _ := e.register(chatgpt)
	f := authzForm(id, "Alice", pass)
	f.Set("redirect_uri", "https://chatgpt.com/connector/oauth/other")
	if resp, _ := e.do("POST", "/oauth/authorize", f, nil); resp.StatusCode != 400 || resp.Header.Get("Location") != "" {
		t.Fatalf("unregistered sibling callback accepted: %d", resp.StatusCode)
	}
	f.Set("redirect_uri", chatgpt)
	resp, _ := e.do("POST", "/oauth/authorize", f, nil)
	if resp.StatusCode != 302 || !strings.HasPrefix(resp.Header.Get("Location"), chatgpt+"?") {
		t.Fatalf("registered wildcard callback rejected: %d", resp.StatusCode)
	}
	u, _ := url.Parse(resp.Header.Get("Location"))
	resp, _ = e.do("POST", "/oauth/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {id},
		"code": {u.Query().Get("code")}, "redirect_uri": {"https://chatgpt.com/connector/oauth/other"},
		"code_verifier": {verifier}}, nil)
	if resp.StatusCode != 400 {
		t.Fatalf("token exchange with unregistered callback: %d", resp.StatusCode)
	}
}

func TestAuthorizeRejectsBadRequestsWithoutRedirectingUntrusted(t *testing.T) {
	e := newEnv(t)
	id, _, _ := e.register(redirect)
	f := authzForm(id, "Alice", pass)
	f.Set("redirect_uri", "https://client.example/callback/")
	if resp, _ := e.do("POST", "/oauth/authorize", f, nil); resp.StatusCode != 400 || resp.Header.Get("Location") != "" {
		t.Fatal("untrusted redirect URI redirected")
	}
	for _, mutate := range []func(url.Values){
		func(f url.Values) { f.Del("code_challenge") },
		func(f url.Values) { f.Set("code_challenge_method", "plain") },
		func(f url.Values) { f.Set("response_type", "token") },
	} {
		f := authzForm(id, "Alice", pass)
		mutate(f)
		resp, _ := e.do("POST", "/oauth/authorize", f, nil)
		if resp.StatusCode != 302 || !strings.Contains(resp.Header.Get("Location"), "error=") ||
			strings.Contains(resp.Header.Get("Location"), "code=") {
			t.Fatalf("bad request not refused: %d %s", resp.StatusCode, resp.Header.Get("Location"))
		}
	}
}

// ---- failed-password limit (H3) ----

func TestPasswordAttemptLimitIsPerActor(t *testing.T) {
	e := newEnv(t)
	id, _, _ := e.register(redirect)
	for i := 0; i < maxFailures; i++ {
		if resp, _ := e.authorize(id, "Alice", "wrong password!"); resp.StatusCode != 401 {
			t.Fatalf("attempt %d: %d", i, resp.StatusCode)
		}
	}
	resp, _ := e.authorize(id, "Alice", pass)
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("limit not enforced, even the right password is refused: %d", resp.StatusCode)
	}
	// Another actor is unaffected.
	if resp, _ := e.authorize(id, "Doc", pass); resp.StatusCode != 302 {
		t.Fatalf("Doc affected by Alice's failures: %d", resp.StatusCode)
	}
	// Unknown labels are limited identically, so limiting reveals nothing.
	for i := 0; i < maxFailures; i++ {
		e.authorize(id, "Nobody", pass)
	}
	if resp, _ := e.authorize(id, "Nobody", pass); resp.StatusCode != 429 {
		t.Fatalf("unknown label not limited: %d", resp.StatusCode)
	}
	// The window passes.
	e.now = e.now.Add(failureWindow + time.Second)
	if resp, _ := e.authorize(id, "Alice", pass); resp.StatusCode != 302 {
		t.Fatalf("still blocked after window: %d", resp.StatusCode)
	}
}

// ---- logging (H5) ----

func TestLogsContainNoSecrets(t *testing.T) {
	e := newEnv(t)
	e.thread("Alice")
	id, _, _ := e.register(redirect)
	q := authzForm(id, "", "")
	q.Del("actor")
	q.Del("password")
	e.do("GET", "/oauth/authorize?"+q.Encode(), nil, nil)
	e.authorize(id, "Alice", "wrong-secret-password")
	code := codeFrom(t, must(e.authorize(id, "Alice", pass)))
	_, body := e.exchange(id, code)
	var tk tokens
	json.Unmarshal(body, &tk)
	e.mcpStatus(tk.Access)
	e.mcpStatus("bogus-bearer-value")

	logs := e.logs.String()
	if !strings.Contains(logs, "/oauth/authorize") || !strings.Contains(logs, "/mcp") {
		t.Fatalf("expected request logging, got %q", logs)
	}
	for name, secret := range map[string]string{
		"password": pass, "wrong password": "wrong-secret-password", "code": code,
		"access token": tk.Access, "refresh token": tk.Refresh, "verifier": verifier,
		"challenge": challenge(verifier), "client id": id, "bearer": "bogus-bearer-value",
		"state": "st-1", "Authorization": "Authorization", "query": "code_challenge",
	} {
		if strings.Contains(logs, secret) {
			t.Fatalf("logs contain %s (%q):\n%s", name, secret, logs)
		}
	}
}

// /mcp is a bearer-token API, not a browser form: behind a proxy or tunnel the
// listener is loopback while Host is the public name, and clients may send no
// Origin or an unrelated one. None of that may cause a 403 for a valid token.
func TestAuthenticatedMCPIgnoresHostAndOrigin(t *testing.T) {
	e := newEnv(t)
	tk := e.login("Alice")
	for name, tc := range map[string]struct{ host, origin string }{
		"no origin, loopback host":    {"", ""},
		"public host, no origin":      {"roundtable.example", ""},
		"public host, foreign origin": {"roundtable.example", "https://chatgpt.com"},
		"public host, public origin":  {"roundtable.example", public},
		"public host, opaque origin":  {"roundtable.example", "null"},
	} {
		req, _ := http.NewRequest("POST", e.ts.URL+"/mcp",
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_threads","arguments":{}}}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+tk.Access)
		if tc.host != "" {
			req.Host = tc.host
		}
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		resp, err := e.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", name, resp.StatusCode)
		}
	}
}

func (e *env) loginOwner(principal string) *http.Cookie {
	e.t.Helper()
	if err := e.st.SetOwnerPassword(principal, pass); err != nil {
		e.t.Fatal(err)
	}
	form := url.Values{"principal": {principal}, "password": {pass}}
	resp, err := e.http.PostForm(e.ts.URL+"/login", form)
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		e.t.Fatalf("login failed: status %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == ownerCookieName {
			return c
		}
	}
	e.t.Fatal("no session cookie received")
	return nil
}

func (e *env) getCSRF(cookie *http.Cookie, path string) string {
	e.t.Helper()
	req, _ := http.NewRequest("GET", e.ts.URL+path, nil)
	req.AddCookie(cookie)
	resp, err := e.http.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	idx := strings.Index(s, `name="csrf_token" value="`)
	if idx == -1 {
		e.t.Fatal("csrf_token not found in page")
	}
	start := idx + len(`name="csrf_token" value="`)
	end := strings.Index(s[start:], `"`)
	if end == -1 {
		e.t.Fatal("malformed csrf token")
	}
	return s[start : start+end]
}

func TestOwnerWebAuthAndSessions(t *testing.T) {
	e := newEnv(t)

	// Unauthenticated GET / redirects to /login
	resp, err := e.http.Get(e.ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Fatalf("expected redirect to /login, got status %d location %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// POST /login with wrong password returns 401
	if err := e.st.SetOwnerPassword("admin", pass); err != nil {
		t.Fatal(err)
	}
	resp, err = e.http.PostForm(e.ts.URL+"/login", url.Values{"principal": {"admin"}, "password": {"wrong"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}

	// Successful login
	cookie := e.loginOwner("admin")
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie flags insecure: %+v", cookie)
	}

	// Authenticated GET / returns 200 and security headers
	req, _ := http.NewRequest("GET", e.ts.URL+"/", nil)
	req.AddCookie(cookie)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("missing security headers: %+v", resp.Header)
	}

	// POST /logout clears session
	csrf := e.getCSRF(cookie, "/")
	req, _ = http.NewRequest("POST", e.ts.URL+"/logout", strings.NewReader(url.Values{"csrf_token": {csrf}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 after logout, got %d", resp.StatusCode)
	}

	// Following with old cookie redirects to /login
	req, _ = http.NewRequest("GET", e.ts.URL+"/", nil)
	req.AddCookie(cookie)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("revoked cookie should redirect, got %d", resp.StatusCode)
	}
}

func TestOwnerBoundaryProtection(t *testing.T) {
	e := newEnv(t)
	cookie := e.loginOwner("admin")
	tk := e.login("Alice")

	// 1. AI Bearer token to owner route rejected
	req, _ := http.NewRequest("GET", e.ts.URL+"/", nil)
	req.Header.Set("Authorization", "Bearer "+tk.Access)
	resp, err := e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Bearer token on owner route should return 401, got %d", resp.StatusCode)
	}

	// 2. Owner cookie on /mcp rejected
	req, _ = http.NewRequest("POST", e.ts.URL+"/mcp", strings.NewReader(`{}`))
	req.AddCookie(cookie)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Owner cookie on /mcp should return 401, got %d", resp.StatusCode)
	}
}

func TestOwnerThreadLifecycleAndGrants(t *testing.T) {
	e := newEnv(t)
	cookie := e.loginOwner("admin")
	csrf := e.getCSRF(cookie, "/")

	// CSRF validation on thread creation
	badReq, _ := http.NewRequest("POST", e.ts.URL+"/threads", strings.NewReader(url.Values{"title": {"t1"}, "csrf_token": {"bad"}}.Encode()))
	badReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badReq.AddCookie(cookie)
	resp, err := e.http.Do(badReq)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 on invalid CSRF, got %d", resp.StatusCode)
	}

	// Create thread with Alice granted
	createForm := url.Values{
		"title":      {"V1 Launch"},
		"actors":     {"Alice"},
		"csrf_token": {csrf},
	}
	req, _ := http.NewRequest("POST", e.ts.URL+"/threads", strings.NewReader(createForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 after create, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	tid := strings.TrimPrefix(loc, "/threads/")

	// Owner posts a message
	csrf = e.getCSRF(cookie, loc)
	postForm := url.Values{"content": {"Welcome team"}, "csrf_token": {csrf}}
	req, _ = http.NewRequest("POST", e.ts.URL+loc+"/messages", strings.NewReader(postForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 after post, got %d", resp.StatusCode)
	}

	// Alice reads it via MCP tool get_thread
	tkAlice := e.login("Alice")
	csAlice := e.session(tkAlice.Access)
	res, isErr := call(e.t, csAlice, "get_thread", map[string]any{"thread_id": tid})
	if isErr {
		t.Fatal("Alice call get_thread failed")
	}
	events := res["events"].([]any)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev0 := events[0].(map[string]any)
	if ev0["actor_label"] != "owner" || ev0["content"] != "Welcome team" {
		t.Fatalf("Alice saw wrong event: %+v", ev0)
	}

	// Doc cannot read it yet
	tkDoc := e.login("Doc")
	csDoc := e.session(tkDoc.Access)
	_, isErr = call(e.t, csDoc, "get_thread", map[string]any{"thread_id": tid})
	if !isErr {
		t.Fatal("Doc should not have access yet")
	}

	// Grant Doc via web
	grantForm := url.Values{"actor": {"Doc"}, "csrf_token": {csrf}}
	req, _ = http.NewRequest("POST", e.ts.URL+loc+"/grants", strings.NewReader(grantForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 after grant, got %d", resp.StatusCode)
	}

	// Doc can now read
	_, isErr = call(e.t, csDoc, "get_thread", map[string]any{"thread_id": tid})
	if isErr {
		t.Fatal("Doc should be able to read after grant")
	}

	// Cross-principal grant attempt (Berry belongs to berry-owner)
	badGrantForm := url.Values{"actor": {"Berry"}, "csrf_token": {csrf}}
	req, _ = http.NewRequest("POST", e.ts.URL+loc+"/grants", strings.NewReader(badGrantForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 when granting cross-principal actor, got %d", resp.StatusCode)
	}

	// Revoke Doc via web
	revokeForm := url.Values{"actor": {"Doc"}, "csrf_token": {csrf}}
	req, _ = http.NewRequest("POST", e.ts.URL+loc+"/revokes", strings.NewReader(revokeForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 after revoke, got %d", resp.StatusCode)
	}

	// Doc immediately loses access
	_, isErr = call(e.t, csDoc, "get_thread", map[string]any{"thread_id": tid})
	if !isErr {
		t.Fatal("Doc should have lost access after revoke")
	}

	// Tombstone the thread
	tombForm := url.Values{"csrf_token": {csrf}}
	req, _ = http.NewRequest("POST", e.ts.URL+loc+"/tombstone", strings.NewReader(tombForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 after tombstone, got %d", resp.StatusCode)
	}

	// Alice loses access immediately
	_, isErr = call(e.t, csAlice, "get_thread", map[string]any{"thread_id": tid})
	if !isErr {
		t.Fatal("Alice should have lost access to tombstoned thread")
	}

	// Further writes fail
	req, _ = http.NewRequest("POST", e.ts.URL+loc+"/messages", strings.NewReader(postForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("posting to tombstoned thread should fail, got %d", resp.StatusCode)
	}

	// Owner can still read audit view
	req, _ = http.NewRequest("GET", e.ts.URL+loc, nil)
	req.AddCookie(cookie)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("owner should be able to view tombstoned thread, got %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "Tombstoned") {
		t.Fatal("thread page did not render tombstone status")
	}
}

func TestOwnerThreadIsolation(t *testing.T) {
	e := newEnv(t)
	cookieAdmin := e.loginOwner("admin")
	cookieAlex := e.loginOwner("alex")

	// Admin creates thread
	csrfW := e.getCSRF(cookieAdmin, "/")
	reqW, _ := http.NewRequest("POST", e.ts.URL+"/threads", strings.NewReader(url.Values{
		"title":      {"Admin Thread"},
		"csrf_token": {csrfW},
	}.Encode()))
	reqW.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqW.AddCookie(cookieAdmin)
	resp, err := e.http.Do(reqW)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	tAdminID := strings.TrimPrefix(resp.Header.Get("Location"), "/threads/")

	// Alex creates thread
	csrfA := e.getCSRF(cookieAlex, "/")
	reqA, _ := http.NewRequest("POST", e.ts.URL+"/threads", strings.NewReader(url.Values{
		"title":      {"Alex Thread"},
		"csrf_token": {csrfA},
	}.Encode()))
	reqA.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqA.AddCookie(cookieAlex)
	resp, err = e.http.Do(reqA)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	tAlexID := strings.TrimPrefix(resp.Header.Get("Location"), "/threads/")

	// Admin lists threads
	req, _ := http.NewRequest("GET", e.ts.URL+"/", nil)
	req.AddCookie(cookieAdmin)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	s := string(b)
	if !strings.Contains(s, tAdminID) || strings.Contains(s, tAlexID) {
		t.Fatalf("Admin's list should contain only Admin's threads: %s", s)
	}

	// Admin attempts to access Alex's thread detail -> 404
	req, _ = http.NewRequest("GET", e.ts.URL+"/threads/"+tAlexID, nil)
	req.AddCookie(cookieAdmin)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 accessing another owner's thread, got %d", resp.StatusCode)
	}
}

func TestOwnerMarkMessageAndThreadWeb(t *testing.T) {
	e := newEnv(t)
	cookie := e.loginOwner("admin")

	// Create thread
	csrf := e.getCSRF(cookie, "/")
	req, _ := http.NewRequest("POST", e.ts.URL+"/threads", strings.NewReader(url.Values{
		"title":      {"Sensitive Thread"},
		"csrf_token": {csrf},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err := e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	tid := strings.TrimPrefix(loc, "/threads/")

	// Post message as owner
	csrf = e.getCSRF(cookie, loc)
	req, _ = http.NewRequest("POST", e.ts.URL+loc+"/messages", strings.NewReader(url.Values{
		"content":    {"Secret plaintext payload"},
		"csrf_token": {csrf},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// Get message ID from thread page
	req, _ = http.NewRequest("GET", e.ts.URL+loc, nil)
	req.AddCookie(cookie)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), "Secret plaintext payload") {
		t.Fatal("expected message to be rendered")
	}

	// Retrieve event id from store
	opage, err := e.st.GetOwnerThread(tid, "admin")
	if err != nil || len(opage.Events) == 0 {
		t.Fatalf("failed to retrieve event from store: %v", err)
	}
	msgID := opage.Events[0].ID

	// Mark message for deletion via web
	csrf = e.getCSRF(cookie, loc)
	req, _ = http.NewRequest("POST", fmt.Sprintf("%s/threads/%s/messages/%d/delete", e.ts.URL, tid, msgID), strings.NewReader(url.Values{
		"csrf_token": {csrf},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 after marking message, got %d", resp.StatusCode)
	}

	// Verify message payload is immediately hidden
	req, _ = http.NewRequest("GET", e.ts.URL+loc, nil)
	req.AddCookie(cookie)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	pageHTML := string(b)
	if strings.Contains(pageHTML, "Secret plaintext payload") {
		t.Fatal("secret payload should be hidden immediately after marking")
	}
	if !strings.Contains(pageHTML, "[Marked for deletion]") {
		t.Fatal("expected [Marked for deletion] placeholder on page")
	}

	// Mark whole thread for deletion via web
	csrf = e.getCSRF(cookie, loc)
	req, _ = http.NewRequest("POST", e.ts.URL+loc+"/delete", strings.NewReader(url.Values{
		"csrf_token": {csrf},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 after marking thread, got %d", resp.StatusCode)
	}

	// Verify thread page shows Marked for Deletion banner
	req, _ = http.NewRequest("GET", e.ts.URL+loc, nil)
	req.AddCookie(cookie)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), "Marked for Deletion") {
		t.Fatal("expected Marked for Deletion status on thread page")
	}

	// Verify thread list shows badge and GC link with count
	req, _ = http.NewRequest("GET", e.ts.URL+"/", nil)
	req.AddCookie(cookie)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	listHTML := string(b)
	if !strings.Contains(listHTML, "Garbage Collection") {
		t.Fatal("expected Garbage Collection link on threads list")
	}
}

func TestOwnerGarbageCollectionWeb(t *testing.T) {
	e := newEnv(t)
	cookie := e.loginOwner("admin")

	// Create and mark thread
	csrf := e.getCSRF(cookie, "/")
	req, _ := http.NewRequest("POST", e.ts.URL+"/threads", strings.NewReader(url.Values{
		"title":      {"GC Target Thread"},
		"csrf_token": {csrf},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err := e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	tid := strings.TrimPrefix(loc, "/threads/")

	// Post message
	csrf = e.getCSRF(cookie, loc)
	req, _ = http.NewRequest("POST", e.ts.URL+loc+"/messages", strings.NewReader(url.Values{
		"content":    {"Erase me forever"},
		"csrf_token": {csrf},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// Mark thread for deletion
	csrf = e.getCSRF(cookie, loc)
	req, _ = http.NewRequest("POST", e.ts.URL+loc+"/delete", strings.NewReader(url.Values{
		"csrf_token": {csrf},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// Visit /gc dashboard
	req, _ = http.NewRequest("GET", e.ts.URL+"/gc", nil)
	req.AddCookie(cookie)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	gcHTML := string(b)
	if !strings.Contains(gcHTML, "Run Garbage Collection Now") {
		t.Fatal("expected GC confirmation button")
	}

	// Try POST /gc without CSRF -> 403
	req, _ = http.NewRequest("POST", e.ts.URL+"/gc", strings.NewReader(""))
	req.AddCookie(cookie)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 on POST /gc without CSRF, got %d", resp.StatusCode)
	}

	// POST /gc with CSRF -> 303
	csrfGC := e.getCSRF(cookie, "/gc")
	req, _ = http.NewRequest("POST", e.ts.URL+"/gc", strings.NewReader(url.Values{
		"csrf_token": {csrfGC},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 after GC confirm, got %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Location"), "/gc?done=1") {
		t.Fatalf("unexpected redirect target: %s", resp.Header.Get("Location"))
	}

	// Check thread page now returns 404
	req, _ = http.NewRequest("GET", e.ts.URL+loc, nil)
	req.AddCookie(cookie)
	resp, err = e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for completely deleted thread, got %d", resp.StatusCode)
	}

	// Verify in store via tid
	_, err = e.st.GetOwnerThread(tid, "admin")
	if err == nil || err.Error() != store.ErrForbidden.Error() {
		t.Fatalf("expected ErrForbidden for deleted thread %s, got %v", tid, err)
	}
}

func TestDeletionAndGCBoundaryEnforcement(t *testing.T) {
	e := newEnv(t)
	// Register actor and obtain token
	tk := e.login("Alice")

	// Bearer token cannot call owner delete or GC routes
	endpoints := []string{"/threads/some-id/delete", "/threads/some-id/messages/1/delete", "/gc"}
	for _, ep := range endpoints {
		req, _ := http.NewRequest("POST", e.ts.URL+ep, strings.NewReader(""))
		req.Header.Set("Authorization", "Bearer "+tk.Access)
		resp, err := e.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 for bearer token on %s, got %d", ep, resp.StatusCode)
		}
	}

	// Owner session cookie cannot call /mcp
	cookie := e.loginOwner("admin")
	req, _ := http.NewRequest("POST", e.ts.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	resp, err := e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for owner cookie on /mcp, got %d", resp.StatusCode)
	}
}
