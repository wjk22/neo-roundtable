package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/wjk22/neo-roundtable/internal/store"
)

type listInput struct{}

type getThreadInput struct {
	ThreadID string `json:"thread_id" jsonschema:"thread to read"`
	Limit    *int   `json:"limit,omitempty" jsonschema:"page size, 1-100, default 10"`
	BeforeID *int64 `json:"before_id,omitempty" jsonschema:"return only events older than this event id"`
}

type postMessageInput struct {
	ThreadID string  `json:"thread_id" jsonschema:"thread to post to"`
	Content  *string `json:"content,omitempty" jsonschema:"message text, or an optional short note when ref_id is set"`
	RefID    *int64  `json:"ref_id,omitempty" jsonschema:"id of an existing event to reference or forward"`
	Relation *string `json:"relation,omitempty" jsonschema:"'reference' or 'forward'; required with ref_id"`
}

// identityFrom returns the identity stored in the validated token grant. It is
// the only place an MCP request's principal/actor is read.
func identityFrom(req *mcp.CallToolRequest) (store.Identity, bool) {
	if req.Extra == nil || req.Extra.TokenInfo == nil {
		return store.Identity{}, false
	}
	actor, _ := req.Extra.TokenInfo.Extra["actor"].(string)
	principal := req.Extra.TokenInfo.UserID
	return store.Identity{PrincipalID: principal, ActorLabel: actor}, principal != "" && actor != ""
}

func (s *Server) toolError(err error) error {
	switch {
	case errors.Is(err, store.ErrForbidden):
		return store.ErrForbidden
	case errors.Is(err, store.ErrInvalid):
		return err
	default:
		s.log.Error("tool failure", "err", err)
		return errors.New("internal error")
	}
}

func result(v any) (*mcp.CallToolResult, any, error) {
	text, err := json.Marshal(v)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content:           []mcp.Content{&mcp.TextContent{Text: string(text)}},
		StructuredContent: v,
	}, nil, nil
}

func (s *Server) newMCPServer() *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "neo-roundtable", Version: "0.2.0"}, nil)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_threads",
		Description: "List private threads visible to the authenticated actor.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ listInput) (*mcp.CallToolResult, any, error) {
		who, ok := identityFrom(req)
		if !ok {
			return nil, nil, errors.New("unauthenticated")
		}
		threads, err := s.store.ListThreads(who)
		if err != nil {
			return nil, nil, s.toolError(err)
		}
		return result(map[string]any{"threads": threads})
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_thread",
		Description: "Read a bounded newest-first page of an authorized thread.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in getThreadInput) (*mcp.CallToolResult, any, error) {
		who, ok := identityFrom(req)
		if !ok {
			return nil, nil, errors.New("unauthenticated")
		}
		limit := 10
		if in.Limit != nil {
			limit = *in.Limit
		}
		page, err := s.store.GetThread(in.ThreadID, who, limit, in.BeforeID)
		if err != nil {
			return nil, nil, s.toolError(err)
		}
		return result(page)
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "post_message",
		Description: "Append a message or reference event to an authorized thread.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in postMessageInput) (*mcp.CallToolResult, any, error) {
		who, ok := identityFrom(req)
		if !ok {
			return nil, nil, errors.New("unauthenticated")
		}
		ev, err := s.store.PostMessage(in.ThreadID, who, in.Content, in.RefID, in.Relation)
		if err != nil {
			return nil, nil, s.toolError(err)
		}
		return result(ev)
	})
	return srv
}

// invalidTokenWriter adds error="invalid_token" to the 401 challenge when the
// client presented a token.
type invalidTokenWriter struct {
	http.ResponseWriter
	sent, wrote bool
}

func (w *invalidTokenWriter) WriteHeader(status int) {
	if w.wrote {
		return
	}
	w.wrote = true
	if status == http.StatusUnauthorized && w.sent {
		h := w.Header()
		if c := h.Get("WWW-Authenticate"); c != "" {
			h.Set("WWW-Authenticate", c+`, error="invalid_token"`)
		}
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *invalidTokenWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *invalidTokenWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *invalidTokenWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// mcpHandler serves the single fixed /mcp endpoint. The Bearer token, its
// expiry and the fixed audience are validated against the database on every
// request; principal and actor come from the stored grant only.
func (s *Server) mcpHandler() http.Handler {
	srv := s.newMCPServer()
	inner := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{
			Stateless:                    true,
			PropagateRequestCancellation: true,
			// The SDK's DNS-rebinding guard 403s any non-loopback Host on a
			// loopback listener, which is exactly how the service runs behind
			// a proxy/tunnel. Safe to disable here: this handler is wrapped by
			// RequireBearerToken and is the only one using the SDK. DNS
			// rebinding needs a browser script to ride ambient credentials,
			// but /mcp accepts only an Authorization: Bearer token that such a
			// script cannot obtain (no cookies, no cross-origin token access),
			// so the guard would protect nothing the token check doesn't.
			DisableLocalhostProtection: true,
		},
	)
	verify := func(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		who, exp, ok := s.store.AccessIdentity(token, s.resource())
		if !ok {
			return nil, auth.ErrInvalidToken
		}
		return &auth.TokenInfo{
			Expiration: time.Unix(exp, 0),
			UserID:     who.PrincipalID,
			Extra:      map[string]any{"actor": who.ActorLabel},
		}, nil
	}
	mw := auth.RequireBearerToken(verify, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: s.publicURL + "/.well-known/oauth-protected-resource/mcp",
	})(inner)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie(ownerCookieName); err == nil && cookie.Value != "" {
			http.Error(w, "owner session cookies are not permitted on /mcp", http.StatusUnauthorized)
			return
		}
		mw.ServeHTTP(&invalidTokenWriter{ResponseWriter: w, sent: r.Header.Get("Authorization") != ""}, r)
	})
}
