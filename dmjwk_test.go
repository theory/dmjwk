package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOptions(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		test  string
		opts  *Options
		hosts []string
	}{
		{
			test: "no_hosts",
			opts: &Options{},
		},
		{
			test: "dupe_hosts",
			opts: &Options{
				HostNames: []string{"x", "x", "y", "x"},
			},
			hosts: []string{"x", "y"},
		},
		{
			test: "overlapping_hosts",
			opts: &Options{
				HostNames: []string{"x", "localhost", "y"},
			},
			hosts: []string{"x", "y"},
		},
	} {
		t.Run(tc.test, func(t *testing.T) {
			t.Parallel()
			a := assert.New(t)

			hosts := append([]string{"localhost", "localhost4", "localhost6", "localhost.localdomain"}, tc.hosts...)
			a.Equal(hosts, tc.opts.dnsNames())
		})
	}
}

func TestKeyset(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		test string
		opts Options
	}{
		{
			test: "no_kids",
			opts: Options{},
		},
		{
			test: "one_kid",
			opts: Options{Kids: []string{"foo"}},
		},
		{
			test: "multiple_kids",
			opts: Options{Kids: []string{"a", "b", "😀"}},
		},
	} {
		t.Run(tc.test, func(t *testing.T) {
			t.Parallel()
			a := assert.New(t)
			r := require.New(t)

			set, err := keyset(&tc.opts)
			a.NotNil(set)
			r.NoError(err)

			keys, err := set.KeyReadAll(t.Context())
			r.NoError(err)
			if tc.opts.Kids == nil {
				// Should have one key with no KID.
				a.Len(keys, 1)
				key, err := set.KeyRead(t.Context(), "")
				r.NoError(err)
				a.NotNil(key.Key())
			} else {
				// Should have a key for each KID.
				a.Len(keys, len(tc.opts.Kids))
				for _, kid := range tc.opts.Kids {
					key, err := set.KeyRead(t.Context(), kid)
					r.NoError(err)
					a.NotNil(key.Key())
				}
			}
		})
	}
}

func TestMux(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		test   string
		opts   Options
		form   url.Values
		client string
		code   string
		msg    string
	}{
		{
			test: "no_grant_type",
			opts: Options{},
			code: "invalid_request",
			msg:  "missing grant_type",
		},
		{
			test: "success",
			opts: Options{Kids: []string{"hello"}},
			form: url.Values{
				"grant_type": []string{"password"},
				"username":   []string{"theory"},
				"password":   []string{"dGhlb3J5"},
			},
		},
		{
			test:   "success_with_basic_auth",
			opts:   Options{Kids: []string{"hello"}},
			client: "some client",
			form: url.Values{
				"grant_type": []string{"password"},
				"username":   []string{"theory"},
				"password":   []string{"dGhlb3J5"},
			},
		},
		{
			test: "multiple_kids_success",
			opts: Options{Kids: []string{"a", "b", "😀"}},
			form: url.Values{
				"grant_type": []string{"password"},
				"username":   []string{"bagel"},
				"password":   []string{"YmFnZWw"},
			},
		},
	} {
		t.Run(tc.test, func(t *testing.T) {
			t.Parallel()
			r := require.New(t)

			// Create a keyset and get the public JWK set.
			set, err := keyset(&tc.opts)
			r.NoError(err)

			// Test fetching the JWKs and OpenAPI.
			mux, err := newMux(&tc.opts, set)
			r.NoError(err)
			makeJWKsRequest(t, mux, set)
			makeOpenAPIRequest(t, mux)

			// Test authorization.
			makeAuthRequest(t, authTest{
				handler: mux,
				opts:    &tc.opts,
				set:     set,
				form:    tc.form,
				code:    tc.code,
				msg:     tc.msg,
			})
		})
	}
}

func TestRandID(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	prev := "67k6ati88u1pm"
	for range 50 {
		id := randID()
		a.NotEmpty(id)
		a.Regexp(`^[123456789abcdefghijkmnopqrstuvwx]{13}$`, id)
		a.NotEqual(prev, id)
		prev = id
	}
}

func TestMakeJWT(t *testing.T) {
	t.Parallel()
	start := time.Now().Truncate(jwt.TimePrecision)

	for _, tc := range []struct {
		test string
		form url.Values
		opts Options
	}{
		{
			test: "basic",
			form: url.Values{"username": []string{"theory"}},
			opts: Options{ExpireAfter: time.Hour * 24},
		},
		{
			test: "iss_and_aud",
			form: url.Values{"username": []string{"theory"}},
			opts: Options{
				ExpireAfter: time.Hour,
				Issuer:      "me",
				Audience:    []string{"people", "pets"},
			},
		},
		{
			test: "form_iss_and_aud",
			form: url.Values{
				"username": []string{"theory"},
				"iss":      []string{"authority"},
				"aud":      []string{"pancakes", "onions"},
			},
			opts: Options{ExpireAfter: time.Hour},
		},
		{
			test: "scope_in_form",
			form: url.Values{"username": []string{"hello"}, "scope": []string{"hi", "bye"}},
			opts: Options{ExpireAfter: time.Hour * 24},
		},
		{
			test: "client_id_in_form",
			form: url.Values{"username": []string{"hello"}, "client_id": []string{"big client"}},
			opts: Options{ExpireAfter: time.Hour * 24},
		},
		{
			test: "kid_in_form",
			form: url.Values{"username": []string{"hello"}, "kid": []string{"b"}},
			opts: Options{ExpireAfter: time.Hour * 24, Kids: []string{"a", "b"}},
		},
		{
			test: "kid_in_options",
			form: url.Values{"username": []string{"❤️ & 🚀"}},
			opts: Options{
				Issuer:      "test",
				Audience:    []string{"everyone"},
				ExpireAfter: time.Hour,
				Kids:        []string{"kiddo"},
			},
		},
		{
			test: "no_expiration",
			form: url.Values{"username": []string{"hello"}, "kid": []string{"b"}},
			opts: Options{Kids: []string{"a", "b"}},
		},
	} {
		t.Run(tc.test, func(t *testing.T) {
			t.Parallel()
			a := assert.New(t)
			r := require.New(t)

			// Create a keyset.
			set, err := keyset(&tc.opts)
			r.NoError(err)

			// Make the JWT.
			req := &http.Request{PostForm: tc.form}
			str, err := makeJWT(t.Context(), &tc.opts, set, req)
			r.NoError(err)
			a.NotEmpty(str)

			// Get the private key.
			kid, priv := getKey(t, set, &tc.opts, tc.form)

			// Validate the token.
			validateToken(t, kid, str, priv, &tc.opts, req, start)
		})
	}
}

func TestSendErr(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		test string
		code string
		msg  string
	}{
		{
			test: "basic",
			code: "invalid_request",
			msg:  "Oops 😬",
		},
		{
			test: "unauthorized_client",
			code: "unauthorized_client",
			msg:  `Insert lots of "stuff" including\backslashes`,
		},
		{
			test: "server_error",
			code: "server_error",
			msg:  "The cat ate the request 🐈",
		},
	} {
		t.Run(tc.test, func(t *testing.T) {
			t.Parallel()
			a := assert.New(t)
			r := require.New(t)

			// Build expected response body.
			exp, err := json.Marshal(map[string]string{
				"error":             tc.code,
				"error_description": tc.msg,
			})
			r.NoError(err)

			// Make the request.
			req := httptest.NewRequestWithContext(
				t.Context(), http.MethodGet, "/", nil,
			)
			w := httptest.NewRecorder()
			a.False(sendErr(w, req, tc.code, tc.msg))

			// Compare the response body.
			resp := w.Result()
			body, err := io.ReadAll(resp.Body)
			r.NoError(err)
			a.JSONEq(string(exp), string(body))
		})
	}
}

func TestCheckRequest(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		test string
		form url.Values
		code string
		msg  string
	}{
		{
			test: "no_grant_type",
			code: "invalid_request",
			msg:  "missing grant_type",
		},
		{
			test: "empty_grant_type",
			form: url.Values{"grant_type": []string{""}},
			code: "invalid_request",
			msg:  "missing grant_type",
		},
		{
			test: "too_many_grant_type",
			form: url.Values{"grant_type": []string{"foo", "bar"}},
			code: "invalid_request",
			msg:  "repeated grant_type parameter",
		},
		{
			test: "bad_grant_type",
			form: url.Values{"grant_type": []string{"authorization_code"}},
			code: "unsupported_grant_type",
			msg:  `grant_type must be "password"`,
		},
		{
			test: "no_username",
			form: url.Values{"grant_type": []string{"password"}},
			code: "invalid_request",
			msg:  "missing username or password",
		},
		{
			test: "empty_username",
			form: url.Values{
				"grant_type": []string{"password"},
				"username":   []string{""},
			},
			code: "invalid_request",
			msg:  "missing username or password",
		},
		{
			test: "no_password",
			form: url.Values{
				"grant_type": []string{"password"},
				"username":   []string{"theory"},
			},
			code: "invalid_request",
			msg:  "missing username or password",
		},
		{
			test: "empty_password",
			form: url.Values{
				"grant_type": []string{"password"},
				"username":   []string{"theory"},
				"password":   []string{""},
			},
			code: "invalid_request",
			msg:  "missing username or password",
		},
		{
			test: "repeat_username",
			form: url.Values{
				"grant_type": []string{"password"},
				"username":   []string{"x", "y"},
				"password":   []string{"x"},
			},
			code: "invalid_request",
			msg:  "repeated username or password parameter",
		},
		{
			test: "repeat_password",
			form: url.Values{
				"grant_type": []string{"password"},
				"username":   []string{"x"},
				"password":   []string{"x", "y"},
			},
			code: "invalid_request",
			msg:  "repeated username or password parameter",
		},
		{
			test: "invalid_password",
			form: url.Values{
				"grant_type": []string{"password"},
				"username":   []string{"theory"},
				"password":   []string{"ur mom"},
			},
			code: "invalid_request",
			msg:  "incorrect password",
		},
		{
			test: "success",
			form: url.Values{
				"grant_type": []string{"password"},
				"username":   []string{"theory"},
				"password":   []string{"dGhlb3J5"},
			},
		},
	} {
		t.Run(tc.test, func(t *testing.T) {
			t.Parallel()
			a := assert.New(t)
			r := require.New(t)

			// Setup a test request.
			req := httptest.NewRequestWithContext(
				t.Context(), http.MethodPost, "/",
				strings.NewReader(tc.form.Encode()),
			)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			// Execute checkRequest.
			ok := checkRequest(w, req)
			resp := w.Result()
			body, err := io.ReadAll(resp.Body)
			r.NoError(err)

			if tc.code == "" {
				// Nothing should be set.
				a.True(ok)
				a.Equal(http.StatusOK, resp.StatusCode)
				a.Empty(body)
				return
			}

			// Should have error response.
			a.Equal(http.StatusBadRequest, resp.StatusCode)
			// Build expected response body.
			exp, err := json.Marshal(map[string]string{
				"error":             tc.code,
				"error_description": tc.msg,
			})
			r.NoError(err)
			a.JSONEq(string(exp), string(body))
		})
	}
}

func TestCheckRequestParseFail(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	r := require.New(t)

	// Setup a request with invalid x-www-form-urlencoded
	req := httptest.NewRequestWithContext(
		t.Context(), http.MethodPost, "/", nil,
	)
	req.Header.Set("Content-Type", "invalid media type")
	w := httptest.NewRecorder()

	// Make the request.
	ok := checkRequest(w, req)
	a.False(ok)
	resp := w.Result()
	body, err := io.ReadAll(resp.Body)
	r.NoError(err)

	// Should have error response.
	a.Equal(http.StatusBadRequest, resp.StatusCode)
	// Build expected response body.
	exp, err := json.Marshal(map[string]string{
		"error":             "invalid_request",
		"error_description": "mime: expected slash after first token",
	})
	r.NoError(err)
	a.JSONEq(string(exp), string(body))
}

func TestSetupAuth(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		test   string
		opts   Options
		client string
		form   url.Values
		code   string
		msg    string
	}{
		{
			test: "no_grant_type",
			code: "invalid_request",
			msg:  "missing grant_type",
		},
		{
			test: "unknown_kid",
			form: url.Values{
				"grant_type": []string{"password"},
				"username":   []string{"theory"},
				"password":   []string{"dGhlb3J5"},
				"kid":        []string{"nonesuch"},
			},
			code: "invalid_request",
			msg:  `key not found: kid "nonesuch"`,
		},
		{
			test: "success",
			opts: Options{ExpireAfter: time.Hour},
			form: url.Values{
				"grant_type": []string{"password"},
				"username":   []string{"theory"},
				"password":   []string{"dGhlb3J5"},
			},
		},
		{
			test:   "success_with_basic_auth",
			opts:   Options{ExpireAfter: time.Hour},
			client: "so basic",
			form: url.Values{
				"grant_type": []string{"password"},
				"username":   []string{"theory"},
				"password":   []string{"dGhlb3J5"},
			},
		},
		{
			test: "success_with_scope",
			form: url.Values{
				"grant_type": []string{"password"},
				"username":   []string{"theory"},
				"password":   []string{"dGhlb3J5"},
				"scope":      []string{"edit", "comment"},
			},
		},
		{
			test: "success_with_client_id",
			form: url.Values{
				"grant_type": []string{"password"},
				"username":   []string{"theory"},
				"password":   []string{"dGhlb3J5"},
				"client_id":  []string{"whatever"},
			},
		},
	} {
		t.Run(tc.test, func(t *testing.T) {
			t.Parallel()

			// Create a keyset.
			set, err := keyset(&tc.opts)
			require.NoError(t, err)

			// Test the request.
			makeAuthRequest(t, authTest{
				handler: setupAuth(&tc.opts, set),
				opts:    &tc.opts,
				set:     set,
				form:    tc.form,
				client:  tc.client,
				code:    tc.code,
				msg:     tc.msg,
			})
		})
	}
}

func TestSetupResource(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		test string
		opts Options
		form url.Values
		body string
		tok  string
		mime string
		code string
		msg  string
	}{
		{
			test: "no_token",
			tok:  "omit",
			code: "invalid_request",
			msg:  "no token present in request",
		},
		{
			test: "invalid_token",
			tok:  "not a JWT",
			code: "invalid_token",
			msg:  "token is malformed: token contains an invalid number of segments",
		},
		{
			test: "success",
			body: "whatever",
		},
		{
			test: "text_success",
			mime: "text/plain",
			body: "I am a resource",
		},
		{
			test: "json_success",
			mime: "application/json",
			body: `{"go": 1}`,
		},
		{
			test: "xml_success",
			mime: "application/xml",
			body: `<foo/>`,
		},
		{
			test: "invalid_issuer",
			opts: Options{Issuer: "me"},
			form: url.Values{"iss": []string{"you"}},
			code: "invalid_token",
			msg:  "token has invalid claims: token has invalid issuer",
		},
		{
			test: "invalid_audience",
			opts: Options{Audience: []string{"you"}},
			form: url.Values{"aud": []string{"me"}},
			code: "invalid_token",
			msg:  "token has invalid claims: token has invalid audience",
		},
	} {
		t.Run(tc.test, func(t *testing.T) {
			t.Parallel()

			// Create a keyset.
			set, err := keyset(&tc.opts)
			require.NoError(t, err)

			// Test the request.
			makeResourceRequest(t, resourceTest{
				handler: setupResource(&tc.opts, set),
				opts:    &tc.opts,
				set:     set,
				form:    tc.form,
				tok:     tc.tok,
				body:    tc.body,
				mime:    tc.mime,
				code:    tc.code,
				msg:     tc.msg,
			})
		})
	}

	t.Run("no_storage", func(t *testing.T) {
		t.Parallel()
		assert.PanicsWithError(
			t, "failed keyfunc: no JWK Set storage given in options",
			func() { setupResource(&Options{}, nil) },
		)
	})
}

func TestServer(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		test string
		opts Options
		form url.Values
		code string
		msg  string
		err  string
	}{
		{
			test: "missing_cert_file",
			opts: Options{KeyPath: "nonesuch"},
			err:  "read",
		},
		{
			test: "no_grant_type",
			opts: Options{},
			code: "invalid_request",
			msg:  "missing grant_type",
		},
		{
			test: "success",
			opts: Options{},
			form: url.Values{
				"grant_type": []string{"password"},
				"username":   []string{"theory"},
				"password":   []string{"dGhlb3J5"},
			},
		},
	} {
		t.Run(tc.test, func(t *testing.T) {
			t.Parallel()
			a := assert.New(t)
			r := require.New(t)

			// Set a config dir.
			tmp := t.TempDir()
			tc.opts.ConfigDir = tmp

			// Create a keyset.
			set, err := keyset(&tc.opts)
			r.NoError(err)

			// Create a server.
			srv, err := server(&tc.opts, set)
			if tc.err != "" {
				r.ErrorContains(err, tc.err)
				return
			}

			require.NoError(t, err)

			// Should have a "ca.pem" in the config dir.
			a.FileExists(filepath.Join(tmp, "ca.pem"))

			// Test fetching the JWKs and openAPI
			makeJWKsRequest(t, srv.Handler, set)
			makeOpenAPIRequest(t, srv.Handler)

			// Test the an auth request.
			makeAuthRequest(t, authTest{
				handler: srv.Handler,
				opts:    &tc.opts,
				set:     set,
				form:    tc.form,
				code:    tc.code,
				msg:     tc.msg,
			})
		})
	}
}

func TestRun(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		test    string
		opts    Options
		sig     func(*testing.T, chan os.Signal, chan error, string, http.Client)
		timeout time.Duration
		exp     string
		err     string
		log     []string
	}{
		{
			test: "interrupt",
			sig: func(t *testing.T, stop chan os.Signal, _ chan error, _ string, _ http.Client) {
				t.Helper()
				stop <- os.Interrupt
			},
			timeout: 5 * time.Second,
			log: []string{
				`{"level":"INFO","msg":"server starting","address":":0"}`,
				`{"level":"INFO","msg":"server shutting down","timeout":5000000000}`,
				`{"level":"INFO","msg":"server shut down"}`,
			},
		},
		{
			test: "timeout",
			sig: func(t *testing.T, stop chan os.Signal, _ chan error, url string, client http.Client) {
				t.Helper()
				// Hold a request open.
				req, err := http.NewRequestWithContext(
					t.Context(), http.MethodGet, url+"/openapi.json", holdOpen{},
				)
				require.NoError(t, err)
				go func(client http.Client, req *http.Request) {
					//nolint:bodyclose
					_, _ = client.Do(req)
				}(client, req)
				time.Sleep(10 * time.Millisecond)
				stop <- os.Interrupt
			},
			timeout: -1,
			exp:     "server shutdown failed",
			err:     "context deadline exceeded",
			log: []string{
				`{"level":"INFO","msg":"server starting","address":":0"}`,
				`{"level":"INFO","msg":"server shutting down","timeout":-1}`,
				`{"level":"ERROR","msg":"server shutdown failed","error":"context deadline exceeded"}`,
			},
		},
		{
			test: "serve_error",
			sig: func(t *testing.T, _ chan os.Signal, serveErr chan error, _ string, _ http.Client) {
				t.Helper()
				serveErr <- errors.New("ouch")
			},
			exp:     "server failed",
			err:     "ouch",
			timeout: 100 * time.Millisecond,
			log: []string{
				`{"level":"INFO","msg":"server starting","address":":0"}`,
				`{"level":"ERROR","msg":"server failed","error":"ouch"}`,
			},
		},
	} {
		t.Run(tc.test, func(t *testing.T) {
			t.Parallel()
			a := assert.New(t)
			r := require.New(t)

			// Set a config dir.
			tmp := t.TempDir()
			tc.opts.ConfigDir = tmp

			// Set up a logger.
			log := &strings.Builder{}
			logger := slog.New(slog.NewJSONHandler(log, &slog.HandlerOptions{
				ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
					// Don't write the time.
					if a.Key == slog.TimeKey {
						return slog.Attr{}
					}
					return a
				},
			}))

			// Create a keyset.
			set, err := keyset(&tc.opts)
			r.NoError(err)

			// Find an available port.
			l := newLocalListener(t)
			addr, ok := l.Addr().(*net.TCPAddr)
			r.True(ok)

			// Create a server.
			//nolint:gosec
			tc.opts.Port = uint32(addr.Port)
			srv, err := server(&tc.opts, set)
			require.NoError(t, err)

			// Load the CA bundle.
			pool := x509.NewCertPool()
			ca, err := os.ReadFile(filepath.Clean(filepath.Join(tmp, "ca.pem")))
			r.NoError(err)
			a.True(pool.AppendCertsFromPEM(ca))

			// Setup utilities.
			cs := make(chan os.Signal, 1)
			serveErr := make(chan error, 1)
			var wg sync.WaitGroup

			// Run the server.
			wg.Go(func() {
				msg, err := run(srv, l, cs, serveErr, logger, tc.timeout)
				a.Equal(tc.exp, msg)
				if tc.err == "" {
					r.NoError(err)
				} else {
					r.EqualError(err, tc.err)
				}
			})

			// Poll for the service to start.
			url, client := makeClient(t, pool, l)
			waitForStart(t, url, client)

			// Send the signal and wait for the server to finish.
			tc.sig(t, cs, serveErr, url, client)
			wg.Wait()

			// Compare the log output.
			for i, l := range tc.log {
				tc.log[i] = strings.Replace(l, ":0", addr.String(), 1)
			}
			a.Equal(strings.Join(tc.log, "\n")+"\n", log.String())
		})
	}
}

func TestExec(t *testing.T) {
	for _, tc := range []struct {
		test string
		env  map[string]string
		args []string
		msg  string
		err  string
	}{
		{
			test: "invalid_option",
			env:  map[string]string{"DMJWK_PORT": "-42"},
			msg:  "cannot process configuration",
			err:  "envconfig.Process: assigning DMJWK_PORT to Port",
		},
		{
			test: "invalid_cert_paths",
			env:  map[string]string{"DMJWK_CERT_PATH": "nonesuch", "DMJWK_KEY_PATH": "nonesuch"},
			msg:  "cannot create server",
			err:  "open",
		},
		{
			test: "version",
			args: []string{"version"},
			msg:  fmt.Sprintf("dmjwk version %v (%v)", version, build),
		},
		{
			test: "unknown_param",
			args: []string{"--lol"},
			msg:  "cannot process arguments",
			err:  "unknown argument `--lol`",
		},
	} {
		t.Run(tc.test, func(t *testing.T) {
			// Set a config dir.
			tmp := t.TempDir()
			t.Setenv("DMJWK_CONFIG_DIR", tmp)

			// Set up environment.
			for k, v := range tc.env {
				t.Setenv(k, v)
			}

			// Make it so.
			msg, err := exec(tc.args)
			if tc.err != "" {
				assert.Equal(t, tc.msg, msg)
				require.ErrorContains(t, err, tc.err)
			} else {
				assert.Equal(t, tc.msg, msg)
				require.NoError(t, err)
			}
		})
	}
}

func makeClient(t *testing.T, pool *x509.CertPool, listener net.Listener) (string, http.Client) {
	t.Helper()

	url := fmt.Sprintf("https://%v/", listener.Addr())
	return url, http.Client{
		Timeout: 100 * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
}

func waitForStart(t *testing.T, url string, client http.Client) {
	t.Helper()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	require.NoError(t, err)

POLL:
	for {
		select {
		case <-ticker.C:
			res, err := client.Do(req)
			if err == nil {
				assert.Equal(t, http.StatusNotFound, res.StatusCode)
				require.NoError(t, res.Body.Close())
				break POLL
			}
		case <-ctx.Done():
			t.Fatalf("timed out waiting for server to start")
		}
	}
}

// newLocalListener configures a listener on a free port selected by the
// system. From https://stackoverflow.com/a/43425461/79202 and
// https://cs.opensource.google/go/go/+/refs/tags/go1.25.0:src/net/http/httptest/server.go;l=68
//
//nolint:noctx
func newLocalListener(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		l, err = net.Listen("tcp6", "[::1]:0")
		require.NoError(t, err)
	}
	return l
}

func getKey(t *testing.T, set *jwkset.MemoryJWKSet, opts *Options, form url.Values) (string, *ecdsa.PrivateKey) {
	t.Helper()

	kid := form.Get("kid")
	if kid == "" {
		kid = opts.Kids[0]
	}
	key, err := set.KeyRead(t.Context(), kid)
	require.NoError(t, err)
	priv, ok := key.Key().(*ecdsa.PrivateKey)
	assert.True(t, ok)
	return kid, priv
}

func makeJWKsRequest(t *testing.T, handler http.Handler, set *jwkset.MemoryJWKSet) {
	t.Helper()
	a := assert.New(t)
	r := require.New(t)

	pub, err := set.JSONPublic(t.Context())
	r.NoError(err)

	req := httptest.NewRequestWithContext(
		t.Context(), http.MethodGet, "/.well-known/jwks.json", nil,
	)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	a.Equal(http.StatusOK, resp.StatusCode)
	a.Equal("application/json", resp.Header.Get("Content-Type"))
	body, err := io.ReadAll(resp.Body)
	r.NoError(err)
	a.JSONEq(string(pub), string(body))
}

func makeOpenAPIRequest(t *testing.T, handler http.Handler) {
	t.Helper()
	a := assert.New(t)
	r := require.New(t)

	exp, err := os.ReadFile("openapi.json")
	r.NoError(err)

	req := httptest.NewRequestWithContext(
		t.Context(), http.MethodGet, "/openapi.json", nil,
	)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	a.Equal(http.StatusOK, resp.StatusCode)
	a.Equal("application/json", resp.Header.Get("Content-Type"))
	body, err := io.ReadAll(resp.Body)
	r.NoError(err)
	a.JSONEq(string(exp), string(body))
}

type authTest struct {
	handler http.Handler
	opts    *Options
	set     *jwkset.MemoryJWKSet
	form    url.Values
	client  string
	code    string
	msg     string
}

type resourceTest struct {
	handler http.Handler
	opts    *Options
	set     *jwkset.MemoryJWKSet
	form    url.Values
	tok     string
	body    string
	mime    string
	code    string
	msg     string
}

func makeAuthRequest(t *testing.T, tc authTest) {
	t.Helper()
	a := assert.New(t)
	r := require.New(t)
	start := time.Now().Truncate(jwt.TimePrecision)

	// Setup a test request.
	req := httptest.NewRequestWithContext(
		t.Context(), http.MethodPost, "/authorization",
		strings.NewReader(tc.form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if tc.client != "" {
		req.SetBasicAuth(tc.client, "")
	}
	w := httptest.NewRecorder()

	tc.handler.ServeHTTP(w, req)
	resp := w.Result()
	a.Equal("application/json", resp.Header.Get("Content-Type"))

	if tc.code != "" {
		// Should return an error.
		a.Equal(http.StatusBadRequest, resp.StatusCode)
		// Build expected response body.
		exp, err := json.Marshal(map[string]string{
			"error":             tc.code,
			"error_description": tc.msg,
		})
		r.NoError(err)
		body, err := io.ReadAll(resp.Body)
		r.NoError(err)
		a.JSONEq(string(exp), string(body))
		return
	}

	// Parse the response.
	res := map[string]any{}
	r.NoError(json.NewDecoder(w.Body).Decode(&res))

	// Get the signing key.
	kid, priv := getKey(t, tc.set, tc.opts, tc.form)

	// Validate the token.
	str, ok := res["access_token"].(string)
	a.True(ok)
	validateToken(t, kid, str, priv, tc.opts, req, start)

	// Verify the rest of the response.
	a.Equal("no-store", resp.Header.Get("Cache-Control"))
	a.Equal("Bearer", res["token_type"])

	if tc.opts.ExpireAfter > 0 {
		a.InEpsilon(float64(tc.opts.ExpireAfter/time.Second), res["expires_in"], 0.02)
	} else {
		_, ok = res["expires_in"]
		a.False(ok)
	}

	if tc.form["scope"] != nil {
		a.Equal(strings.Join(tc.form["scope"], " "), res["scope"])
	} else {
		a.Equal("read", res["scope"])
	}
}

func makeResourceRequest(t *testing.T, tc resourceTest) {
	t.Helper()
	a := assert.New(t)
	r := require.New(t)

	// Setup header values.
	var err error
	if tc.tok == "" {
		tc.tok, err = makeJWT(t.Context(), tc.opts, tc.set, &http.Request{PostForm: tc.form})
		r.NoError(err)
	}

	// Setup a test request.
	req := httptest.NewRequestWithContext(
		t.Context(), http.MethodPost, "/resource",
		strings.NewReader(tc.body),
	)

	if tc.tok != "omit" {
		req.Header.Set("Authorization", "Bearer "+tc.tok)
	}
	if tc.mime != "" {
		req.Header.Set("Content-Type", tc.mime)
	}
	w := httptest.NewRecorder()

	tc.handler.ServeHTTP(w, req)
	resp := w.Result()

	if tc.code != "" {
		// Should return an error.
		a.Equal(http.StatusUnauthorized, resp.StatusCode)
		a.Equal("application/json", resp.Header.Get("Content-Type"))
		a.Equal(
			fmt.Sprintf("Bearer error=%q error_description=%q", tc.code, tc.msg),
			resp.Header.Get("WWW-Authenticate"),
		)
		// Build expected response body.
		exp, err := json.Marshal(map[string]string{
			"error":             tc.code,
			"error_description": tc.msg,
		})
		r.NoError(err)
		body, err := io.ReadAll(resp.Body)
		r.NoError(err)
		a.JSONEq(string(exp), string(body))
		return
	}

	// Validate the response.
	if tc.mime == "" {
		tc.mime = "application/octet-stream"
	}
	a.Equal(http.StatusOK, resp.StatusCode)
	a.Equal(tc.mime, resp.Header.Get("Content-Type"))
	body, err := io.ReadAll(resp.Body)
	r.NoError(err)
	a.Equal(tc.body, string(body))
}

func validateToken(
	t *testing.T,
	kid, str string,
	priv *ecdsa.PrivateKey,
	opts *Options,
	req *http.Request,
	start time.Time,
) {
	t.Helper()
	a := assert.New(t)
	r := require.New(t)
	form := req.PostForm

	// Parse the token.
	claims := &rfc8693Claims{}
	tok, err := jwt.ParseWithClaims(str, claims, func(*jwt.Token) (any, error) {
		return &priv.PublicKey, nil
	})
	r.NoError(err)
	a.NotNil(tok)

	// KID should be set.
	a.Equal(kid, tok.Header[jwkset.HeaderKID])

	// Compare claims.
	str, err = claims.GetIssuer()
	r.NoError(err)
	if iss, ok := form["iss"]; ok {
		a.Equal(iss[0], str)
	} else {
		a.Equal(opts.Issuer, str)
	}

	str, err = claims.GetSubject()
	r.NoError(err)
	a.Equal(form.Get("username"), str)

	iat, err := claims.GetIssuedAt()
	r.NoError(err)
	a.WithinRange(iat.Time, start, time.Now())

	exp, err := claims.GetExpirationTime()
	r.NoError(err)
	if opts.ExpireAfter > 0 {
		a.Equal(exp.Time, iat.Add(opts.ExpireAfter))
	} else {
		a.Nil(exp)
	}

	aud, err := claims.GetAudience()
	r.NoError(err)
	switch {
	case len(form["aud"]) > 0:
		a.Equal(jwt.ClaimStrings(form["aud"]), aud)
	case len(opts.Audience) > 0:
		a.Equal(jwt.ClaimStrings(opts.Audience), aud)
	default:
		a.Nil(aud)
	}

	if len(form["scope"]) > 0 {
		a.Equal(strings.Join(form["scope"], " "), claims.Scope)
	} else {
		a.Empty(claims.Scope)
	}

	if u, _, ok := req.BasicAuth(); ok {
		a.Equal(u, claims.ClientID)
	} else {
		a.Equal(form.Get("client_id"), claims.ClientID)
	}
}

type holdOpen struct{}

func (holdOpen) Read([]byte) (int, error) {
	time.Sleep(time.Second)
	return 0, nil
}
