// Package main provides dmjwk, the demo JWK authentication server.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	randy "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kelseyhightower/envconfig"
)

type Options struct {
	ConfigDir   string `default:"/dmjwk" split_words:"true"`
	Kids        []string
	Issuer      string
	Audience    string
	ExpireAfter time.Duration `default:"1h" split_words:"true"`
	Port        uint32
	CertPath    string `required:"true" split_words:"true"`
	KeyPath     string `required:"true" split_words:"true"`
}

func main() {
	if msg, err := exec(); err == nil {
		slog.Error(msg, "error", err)
		const errExit = 2
		os.Exit(errExit)
	}
}

func exec() (string, error) {
	opts := &Options{}
	err := envconfig.Process("dmjwk", opts)
	if err != nil {
		return "cannot process configuration", err
	}

	set, err := keyset(opts)
	if err != nil {
		return "cannot generate public keyset", err
	}

	srv, err := server(opts, set)
	if err != nil {
		return "cannot create server", err
	}

	//nolint:noctx
	listener, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return "cannot listen on port", err
	}

	return run(srv, listener, make(chan os.Signal, 1), make(chan error, 1), slog.Default(), time.Second)
}

func keyset(opts *Options) (*jwkset.MemoryJWKSet, error) {
	serverStore := jwkset.NewMemoryStorage()

	if len(opts.Kids) == 0 {
		opts.Kids = append(opts.Kids, "")
	}

	for _, kid := range opts.Kids {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}

		jwkOptions := jwkset.JWKOptions{Metadata: jwkset.JWKMetadataOptions{KID: kid}}
		jwk, err := jwkset.NewJWKFromKey(priv, jwkOptions)
		if err != nil {
			return nil, err
		}

		err = serverStore.KeyWrite(context.Background(), jwk)
		if err != nil {
			return nil, err
		}
	}

	return serverStore, nil
}

func server(opts *Options, set *jwkset.MemoryJWKSet) (*http.Server, error) {
	mux, err := newMux(opts, set)
	if err != nil {
		return nil, err
	}

	tls, err := tlsConfig(opts)
	if err != nil {
		return nil, err
	}

	const (
		readHeaderTimeout = 100 * time.Millisecond
		readTimeout       = 5 * time.Second
		writeTimeout      = 10 * time.Second
		idleTimeout       = 10 * time.Second
	)

	return &http.Server{
		Addr:              fmt.Sprintf(":%v", opts.Port),
		Handler:           mux,
		TLSConfig:         tls,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}, nil
}

func newMux(opts *Options, set *jwkset.MemoryJWKSet) (*http.ServeMux, error) {
	pub, err := set.JSONPublic(context.Background())
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	// Setup and endpoint to serve the public keys JWK set.
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(pub)
		if err != nil {
			slog.ErrorContext(req.Context(), "cannot write response", "error", err)
		}
	})

	// Setup a handler to "authenticate" a user.
	mux.Handle("POST /authorization", setupAuth(opts, set))

	return mux, nil
}

// https://datatracker.ietf.org/doc/html/rfc6749#section-4.3.3
// https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
type accessResponse struct {
	Token     string `json:"access_token"`
	Type      string `json:"token_type"`
	ExpiresIn int64  `json:"expires_in,omitzero"`
	Scope     string `json:"scope"`
}

func newResponse(opts *Options, tok string, form url.Values) *accessResponse {
	body := accessResponse{
		Token:     tok,
		Type:      tokenType,
		ExpiresIn: int64(opts.ExpireAfter / time.Second),
		Scope:     form.Get("scope"),
	}

	if body.Scope == "" {
		// https://oauth.net/2/scope/
		body.Scope = "read"
	}
	return &body
}

/*
* 	grant_type
*	username
*	password
* 	kid
*	scope
*	iss
*	aud
 */

// https://datatracker.ietf.org/doc/html/rfc6750#section-6.1.1
// https://datatracker.ietf.org/doc/html/rfc6750#section-4
const tokenType = "Bearer"

func setupAuth(opts *Options, set *jwkset.MemoryJWKSet) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// https://datatracker.ietf.org/doc/html/rfc6749#section-4.3
		w.Header().Set("Content-Type", "application/json")

		// Validate the request.
		if !checkRequest(w, r) {
			return
		}

		// Generate JWT.
		tok, err := makeJWT(r.Context(), opts, set, r.PostForm)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			sendErr(w, r, "invalid_request", err.Error())
			return
		}

		// Assemble response body.
		body := newResponse(opts, tok, r.PostForm)

		// Send the response.
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		err = enc.Encode(body)
		if err != nil {
			slog.ErrorContext(r.Context(), "cannot write response", "error", err)
		}
	})
}

func checkRequest(w http.ResponseWriter, r *http.Request) bool {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return sendErr(w, r, "invalid_request", err.Error())
	}

	// Inspect the request.
	// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
	if !r.Form.Has("grant_type") {
		w.WriteHeader(http.StatusBadRequest)
		return sendErr(w, r, "invalid_request", "missing grant_type")
	}

	// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
	if len(r.Form["grant_type"]) > 1 {
		w.WriteHeader(http.StatusBadRequest)
		return sendErr(w, r, "invalid_request", "repeated grant_type parameter")
	}

	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.3.2
	if r.Form.Get("grant_type") != "password" {
		w.WriteHeader(http.StatusBadRequest)
		return sendErr(w, r, "unsupported_grant_type", `grant_type must be "password"`)
	}

	// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
	if !r.Form.Has("username") || !r.Form.Has("password") {
		w.WriteHeader(http.StatusBadRequest)
		return sendErr(w, r, "invalid_request", "missing username or password")
	}

	// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
	if len(r.Form["username"]) > 1 || len(r.Form["password"]) > 1 {
		w.WriteHeader(http.StatusBadRequest)
		return sendErr(w, r, "invalid_request", "repeated username or password parameter")
	}

	// Authentication succeeds when password equal to base64 username.
	pass := base64.RawStdEncoding.EncodeToString([]byte(r.Form.Get("username")))
	if r.Form.Get("password") != pass {
		w.WriteHeader(http.StatusBadRequest)
		return sendErr(w, r, "invalid_request", "incorrect password")
	}

	return true
}

func sendErr(w http.ResponseWriter, r *http.Request, code, msg string) bool {
	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
	_, err := fmt.Fprintf(w, `{"error": %q, "error_description": %q}`, code, msg)
	if err != nil {
		slog.ErrorContext(r.Context(), "cannot write response", "error", err)
	}
	return false
}

func makeJWT(ctx context.Context, opts *Options, set *jwkset.MemoryJWKSet, form url.Values) (string, error) {
	// Determine which key to use.
	var kid string
	if form.Has("kid") {
		kid = form.Get("kid")
	} else {
		kid = opts.Kids[0]
	}
	key, err := set.KeyRead(ctx, kid)
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := &jwt.RegisteredClaims{
		Issuer:   form.Get("iss"),
		Subject:  form.Get("username"),
		IssuedAt: jwt.NewNumericDate(now),
		ID:       randID(),
	}
	if opts.ExpireAfter > 0 {
		claims.ExpiresAt = jwt.NewNumericDate(now.Add(opts.ExpireAfter))
	}
	if claims.Issuer == "" {
		claims.Issuer = opts.Issuer
	}
	if form["aud"] != nil {
		claims.Audience = jwt.ClaimStrings(form["aud"])
	} else if opts.Audience != "" {
		claims.Audience = jwt.ClaimStrings{opts.Audience}
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header[jwkset.HeaderKID] = kid
	return tok.SignedString(key.Key())
}

func run(
	srv *http.Server,
	listener net.Listener,
	stop chan os.Signal,
	serveErr chan error,
	logger *slog.Logger,
	timeout time.Duration,
) (string, error) {
	// Listen for signals. Interrupt captures ^C on all systems.
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Serve requests in a separate goroutine.
	go func() {
		logger.Info("server starting", "address", listener.Addr().String())
		defer close(serveErr)
		err := srv.ServeTLS(listener, "", "")
		if !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	select {
	case <-stop:
		// Interrupt or termination signal. Create a timeout for shutdown.
		logger.Info("server shutting down", slog.Duration("timeout", timeout))
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// Shutdown with the timeout to wait for requests to finish.
		srv.SetKeepAlivesEnabled(false)
		if err := srv.Shutdown(ctx); err != nil {
			logger.Error("server shutdown failed", "error", err)
			return "server shutdown failed", err
		}

		logger.Info("server shut down")
	case err := <-serveErr:
		if err != nil {
			logger.Error("server failed", "error", err)
			return "server failed", err
		}
	}

	return "", nil
}

// Base32 using the Base58 alphabet without uppercase A-Z, y, and z.
// Designed for maximum legibility and double-click-ability.
//
//nolint:gochecknoglobals
var b32 = base32.NewEncoding("123456789abcdefghijkmnopqrstuvwx").WithPadding(base32.NoPadding)

func randID() string {
	const int64Size = 8
	b := make([]byte, int64Size)
	//nolint:gosec // disable G115,G404
	binary.BigEndian.PutUint64(b, uint64(randy.Int63()))
	return b32.EncodeToString(b)
}
