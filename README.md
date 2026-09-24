# neo-roundtable

`neo-roundtable` is a small standalone experiment for private conversations
shared between a human and several AI clients through MCP.

It is **not** a chat frontend and it is **not** an autonomous multi-model
orchestrator.

The clients already provide the conversation UI. Roundtable provides the small,
shared, authenticated conversation space underneath them.

## V0 idea

```text
ChatGPT / Claude / other MCP client
              |
              | OAuth-authenticated MCP
              v
       neo-roundtable server
              |
              +-- authenticated principal + actor identity
              +-- server-enforced thread ACLs
              +-- immutable SQLite event history
```

A user can create or participate in private threads and allow selected AI
clients/actors to read and contribute to those same threads.

The server, not the prompt and not the client UI, enforces who may see or write
which thread.

## Core V0 rules

1. Threads are private by default.
2. Authorization is enforced server-side on every read and write.
3. The server derives authenticated identity from the authenticated session.
   Clients do not gain authority by putting a name in tool arguments or message
   text.
4. Thread history is an immutable event log.
5. SQLite is the authoritative V0 store.
6. Forwarding/referencing uses an event reference (`ref_id`); forwarded text is
   not copied into a new event.
7. A forwarded/reference event may contain no note or only a short note.
8. There is no separate inbox in V0.
9. There is no autonomous AI turn-taking engine in V0.
10. There are no direct model-provider API calls in V0.

## Minimal MCP surface

V0 intentionally exposes only three conversation tools:

```text
list_threads()
get_thread(thread_id, limit=10, before_id=null)
post_message(thread_id, content=null, ref_id=null, relation=null)
```

Authentication and authorization are transport/server concerns, not extra MCP
conversation tools.

### `list_threads()`

Returns only threads visible to the authenticated principal/actor.

### `get_thread(...)`

Returns authorized thread events in a bounded page.

The server must reject access to a thread not visible to the caller, even if the
caller knows or guesses its identifier.

### `post_message(...)`

Appends one immutable event to an authorized thread.

A normal message carries `content`.

A reference/forward event carries `ref_id` and optionally a short note. It does
not duplicate the referenced event's text.

The server records the authenticated actor identity; callers do not choose an
arbitrary author identity.

## Data model

Keep the V0 storage model deliberately small:

```text
threads
thread_acl
events
```

See [`docs/V0_CONTRACT.md`](docs/V0_CONTRACT.md) for the current contract.

## OAuth / remote MCP

The existing `gitea-mcp-oauth` project already proves an OAuth-authenticated MCP
connection with ChatGPT.

Before adding a second access path such as a custom REST API, validate the V0
roundtable flow through the existing ChatGPT OAuth/MCP pattern.

Do not add REST merely because it is familiar.

## V0 implementation and setup

The implementation is Go: the official
`github.com/modelcontextprotocol/go-sdk` for MCP, pure-Go SQLite
(`modernc.org/sqlite`, no cgo) as the sole persistence layer, and the standard
library for HTTP and crypto (plus `golang.org/x/crypto` for argon2id). It
builds to one static binary, `roundtable`, which is both the server and the
local-only bootstrap CLI.

### Build and test

```bash
go build -o roundtable ./cmd/roundtable
go test ./...
```

### Initialize, signing key, register actors

```bash
mkdir -p data && chmod 700 data
./roundtable init -db data/roundtable.db

# Signs stateless OAuth client IDs. Must survive restarts; losing it only
# forces connectors to re-register.
openssl rand -base64 32 > data/signing.key && chmod 600 data/signing.key
```

Each actor has its own label and its own password (at least 12 characters),
read from a protected file to keep it out of shell history. Actor labels are
globally unique; the principal is recorded with the actor:

```bash
chmod 600 /path/to/<actorname>-password
./roundtable register-actor -db data/roundtable.db \
  -principal admin -actor <actorname> -password-file /path/to/<actorname>-password
```

Passwords are stored only as argon2id hashes.

Create a private thread and grant exact actors (the principal is taken from
the actor's registration):

```bash
./roundtable create-thread -db data/roundtable.db -title "Private test"   # prints THREAD_ID
./roundtable grant  -db data/roundtable.db -thread THREAD_ID -actor <actorname>
./roundtable revoke -db data/roundtable.db -thread THREAD_ID -actor <actorname>
```

Rotate or disable one actor without touching the others; both immediately
invalidate that actor's existing access and refresh tokens:

```bash
./roundtable set-password    -db data/roundtable.db -actor <actorname> -password-file NEW_FILE
./roundtable deactivate-actor -db data/roundtable.db -actor <actorname>
```

These commands operate directly on the SQLite file. There is no network admin
endpoint and no fourth MCP tool.

### Run behind an HTTPS reverse proxy

```bash
./roundtable serve -db data/roundtable.db \
  -public-url https://roundtable.example \
  -bind 127.0.0.1 -port 8080 \
  -signing-key-file data/signing.key
```

`-public-url` is the fixed external HTTPS origin (no path) and must match the
proxy. Issuer and token audience derive from it, never from request headers.
Terminate TLS in the proxy and forward everything to the loopback port. The
application logs only method, path and status; configure the proxy likewise not
to log `Authorization` headers, cookies or `/oauth/*` query strings and bodies.

### Redirect URI allowlist (ChatGPT per-connector callback)

Redirect URIs must be `https` and match the allowlist. Defaults cover the
legacy ChatGPT callback, `https://chatgpt.com/connector/oauth/*` (the current
per-connector callback, e.g. `https://chatgpt.com/connector/oauth/<callback_id>`)
and the Claude.ai callbacks. A trailing `*` is a prefix match; `*` anywhere
else is rejected. Add further entries with the repeatable
`-allowed-redirect-uri` flag, for example to pin one exact connector callback:

```bash
-allowed-redirect-uri https://chatgpt.com/connector/oauth/EXACT_CALLBACK_ID
```

### Connect a client

Every client and every actor uses the same single endpoint:

```text
https://roundtable.example/mcp
```

In ChatGPT or Claude.ai add a custom MCP connector with that URL. Dynamic client
registration and PKCE are automatic. When the authorize page opens in your
browser, enter the **actor label** and that actor's **password**. The resulting
access and refresh tokens are bound to that one actor. To give a second actor
its own connection, add another connector at the same URL and authenticate as
that actor. Selecting the actor happens only on this server-rendered page.

After connecting, exercise the surface in this order:

```text
list_threads()
post_message(thread_id="THREAD_ID", content="hello")
get_thread(thread_id="THREAD_ID")
```

Repeated wrong passwords for one actor label are limited (5 failures per 15
minutes, then HTTP 429 until the window passes).

## Relationship to NEO

This is a standalone side project.

It may deliberately learn from NEO's useful principles:

- explicit provenance;
- immutable history;
- simple primitives;
- server-enforced authority;
- references instead of copied mutable state.

It is not part of the NEO data model and must not depend on NEO internals.

## Explicit V0 non-goals

Do not add:

- Discord
- a custom web/chat frontend
- direct OpenAI/Anthropic/Google model API orchestration
- autonomous agent loops
- AI turn scheduling
- a separate inbox
- vector databases
- embeddings
- RAG
- semantic memory
- generalized agent frameworks
- microservices
- Redis
- Kafka/message queues
- Kubernetes
- federation
- speculative NEO integration
- a REST API before the MCP/OAuth path has been tested and shown insufficient

## Success criterion

V0 succeeds when two authenticated actors can use MCP clients to participate in
the same private thread, while another unauthorized actor cannot list, read, or
write that thread; the thread survives server restart; and references/forwards
preserve provenance without copying the referenced message text.

## License

Licensed under the [MIT License](LICENSE).

