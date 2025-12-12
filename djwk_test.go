package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		test string
		opts Options
		form url.Values
		code string
		msg  string
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

			// Test fetching the JWKs.
			mux, err := newMux(&tc.opts, set)
			makeJWKsRequest(t, mux, set)

			// Test authentication.
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
			opts: Options{ExpireAfter: time.Hour, Issuer: "me", Audience: "people"},
		},
		{
			test: "form_iss_and_aud",
			form: url.Values{
				"username": []string{"theory"},
				"iss":      []string{"authority"},
				"aud":      []string{"pancakes"},
			},
			opts: Options{ExpireAfter: time.Hour},
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
				Audience:    "everyone",
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
			str, err := makeJWT(t.Context(), &tc.opts, set, tc.form)
			r.NoError(err)
			a.NotEmpty(str)

			// Get the private key.
			kid, priv := getKey(t, set, &tc.opts, tc.form)

			// Validate the token.
			tok, err := jwt.Parse(str, func(t *jwt.Token) (any, error) {
				return &priv.PublicKey, nil
			})
			r.NoError(err)
			a.NotNil(tok)

			// KID should be set.
			a.Equal(kid, tok.Header[jwkset.HeaderKID])

			// Compare claims;
			str, err = tok.Claims.GetIssuer()
			r.NoError(err)
			if iss, ok := tc.form["iss"]; ok {
				a.Equal(iss[0], str)
			} else {
				a.Equal(tc.opts.Issuer, str)
			}

			str, err = tok.Claims.GetSubject()
			r.NoError(err)
			a.Equal(tc.form.Get("username"), str)

			iat, err := tok.Claims.GetIssuedAt()
			r.NoError(err)
			a.WithinRange(iat.Time, start, time.Now())

			exp, err := tok.Claims.GetExpirationTime()
			r.NoError(err)
			if tc.opts.ExpireAfter > 0 {
				a.Equal(iat.Add(tc.opts.ExpireAfter), exp.Time)
			} else {
				a.Nil(exp)
			}

			aud, err := tok.Claims.GetAudience()
			r.NoError(err)
			if param, ok := tc.form["aud"]; ok {
				a.Equal(jwt.ClaimStrings{param[0]}, aud)
			} else if tc.opts.Audience != "" {
				a.Equal(jwt.ClaimStrings{tc.opts.Audience}, aud)
			} else {
				a.Nil(aud)
			}
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
			test: "no_password",
			form: url.Values{
				"grant_type": []string{"password"},
				"username":   []string{"theory"},
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
		test string
		opts Options
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
			test: "success_with_scope",
			form: url.Values{
				"grant_type": []string{"password"},
				"username":   []string{"theory"},
				"password":   []string{"dGhlb3J5"},
				"scope":      []string{"all the things"},
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
				code:    tc.code,
				msg:     tc.msg,
			})
		})
	}
}

func TestServer(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()

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
			opts: Options{ConfigDir: tmp, KeyPath: "nonesuch"},
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
			r := require.New(t)

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

			// Test fetching the JWKs.
			makeJWKsRequest(t, srv.Handler, set)

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

func getKey(t *testing.T, set *jwkset.MemoryJWKSet, opts *Options, form url.Values) (string, *ecdsa.PrivateKey) {
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
	a.Equal(resp.Header.Get("Content-Type"), "application/json")
	body, err := io.ReadAll(resp.Body)
	r.NoError(err)
	a.JSONEq(string(pub), string(body))
}

type authTest struct {
	handler http.Handler
	opts    *Options
	set     *jwkset.MemoryJWKSet
	form    url.Values
	code    string
	msg     string
}

func makeAuthRequest(t *testing.T, tc authTest) {
	t.Helper()
	a := assert.New(t)
	r := require.New(t)

	// Setup a test request.
	req := httptest.NewRequestWithContext(
		t.Context(), http.MethodPost, "/authorization",
		strings.NewReader(tc.form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	tc.handler.ServeHTTP(w, req)
	resp := w.Result()
	a.Equal(resp.Header.Get("Content-Type"), "application/json")

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
		a.JSONEq(string(exp), string(body))
		return
	}

	// Parse the response.
	res := map[string]any{}
	r.NoError(json.NewDecoder(w.Body).Decode(&res))

	// Get the signing key.
	kid, priv := getKey(t, tc.set, tc.opts, tc.form)

	// Verify the token.
	str, ok := res["access_token"].(string)
	a.True(ok)
	tok, err := jwt.Parse(str, func(t *jwt.Token) (any, error) {
		return &priv.PublicKey, nil
	})
	r.NoError(err)
	a.NotNil(tok)
	a.Equal(kid, tok.Header[jwkset.HeaderKID])

	// Verify the rest of the response.
	a.Equal("Bearer", res["token_type"])
	if tc.opts.ExpireAfter > 0 {
		a.Equal(float64(tc.opts.ExpireAfter/time.Second), res["expires_in"])
	} else {
		_, ok = res["expires_in"]
		a.False(ok)
	}
}
