// Command roundtable runs the neo-roundtable server and its local-only
// bootstrap/administration commands. Administration operates directly on the
// SQLite file; there is no network admin surface.
package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/wjk22/neo-roundtable/internal/server"
	"github.com/wjk22/neo-roundtable/internal/store"
)

const usage = `usage: roundtable <command> -db PATH [flags]

commands:
  init               create or migrate the database
  serve              run the HTTP server
  set-owner-password -owner P -password-file F
  migrate-v0         -owner P
  register-actor     -principal P -actor A -password-file F
  set-password       -actor A -password-file F   (rotate; revokes A's tokens)
  deactivate-actor   -actor A                    (revokes A's tokens)
  create-thread      [-owner P] [-title T]
  grant              -thread ID -actor A
  revoke             -thread ID -actor A
`

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func readPassword(path string) (string, error) {
	if path == "" {
		return "", errors.New("-password-file is required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

// readSigningKey accepts 32 raw bytes or a base64 encoding of 32 bytes.
func readSigningKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) == 32 {
		return b, nil
	}
	text := string(bytes.TrimSpace(b))
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if d, err := enc.DecodeString(text); err == nil && len(d) == 32 {
			return d, nil
		}
	}
	return nil, errors.New("signing key file must contain 32 random bytes (raw or base64)")
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("missing command")
	}
	cmd := args[0]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	db := fs.String("db", "", "SQLite database path")
	principal := fs.String("principal", "", "principal id")
	actor := fs.String("actor", "", "actor label")
	pwFile := fs.String("password-file", "", "file containing the actor password")
	title := fs.String("title", "", "thread title")
	thread := fs.String("thread", "", "thread id")
	publicURL := fs.String("public-url", "", "canonical https origin, no path")
	bind := fs.String("bind", "127.0.0.1", "listen address")
	port := fs.Int("port", 8080, "listen port")
	keyFile := fs.String("signing-key-file", "", "file with 32 random bytes (raw or base64)")
	var redirects listFlag
	fs.Var(&redirects, "allowed-redirect-uri", "extra allowed redirect URI; trailing * is a prefix match; repeatable")
	owner := fs.String("owner", "", "owner principal id")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *db == "" {
		return errors.New("-db is required")
	}
	st, err := store.Open(*db)
	if err != nil {
		return err
	}
	defer st.Close()

	getOwner := func() string {
		if *owner != "" {
			return *owner
		}
		return *principal
	}

	switch cmd {
	case "init":
		fmt.Println("initialized", *db)
	case "set-owner-password":
		o := getOwner()
		if o == "" {
			return errors.New("-owner or -principal is required")
		}
		pw, err := readPassword(*pwFile)
		if err != nil {
			return err
		}
		if err := st.SetOwnerPassword(o, pw); err != nil {
			return err
		}
		fmt.Println("owner password set; active sessions revoked")
	case "migrate-v0":
		o := getOwner()
		if o == "" {
			return errors.New("-owner or -principal is required")
		}
		n, err := st.MigrateV0Threads(o)
		if err != nil {
			return err
		}
		fmt.Printf("migrated %d threads to owner %s\n", n, o)
	case "register-actor":
		pw, err := readPassword(*pwFile)
		if err != nil {
			return err
		}
		if err := st.RegisterActor(*principal, *actor, pw); err != nil {
			return err
		}
		fmt.Println("actor registered")
	case "set-password":
		pw, err := readPassword(*pwFile)
		if err != nil {
			return err
		}
		if err := st.SetActorPassword(*actor, pw); err != nil {
			return err
		}
		fmt.Println("password rotated; existing tokens revoked")
	case "deactivate-actor":
		if err := st.DeactivateActor(*actor); err != nil {
			return err
		}
		fmt.Println("actor deactivated; existing tokens revoked")
	case "create-thread":
		o := getOwner()
		if o == "" {
			o = "admin"
		}
		id, err := st.CreateThread(*title, o)
		if err != nil {
			return err
		}
		fmt.Println(id)
	case "grant":
		if err := st.Grant(*thread, *actor); err != nil {
			return err
		}
		fmt.Println("grant completed")
	case "revoke":
		if err := st.Revoke(*thread, *actor); err != nil {
			return err
		}
		fmt.Println("revoke completed")
	case "serve":
		if *keyFile == "" {
			return errors.New("-signing-key-file is required")
		}
		key, err := readSigningKey(*keyFile)
		if err != nil {
			return err
		}
		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		srv, err := server.New(server.Config{
			Store:      st,
			PublicURL:  *publicURL,
			SigningKey: key,
			Redirects:  append(append([]string{}, server.DefaultRedirects...), redirects...),
			Logger:     logger,
		})
		if err != nil {
			return err
		}
		addr := net.JoinHostPort(*bind, strconv.Itoa(*port))
		logger.Info("neo-roundtable listening", "addr", addr)
		hs := &http.Server{
			Addr:              addr,
			Handler:           srv.Handler(),
			ReadHeaderTimeout: 10 * time.Second,
		}
		return hs.ListenAndServe()
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
	return nil
}
