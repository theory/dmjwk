package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
		err  string
	}{
		{
			test: "no_kids",
			opts: Options{},
		},
		{
			test: "one_kid",
			opts: Options{Kids: []string{"hello"}},
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

			// Create a keyset and get the public JWK set.
			set, err := keyset(&tc.opts)
			r.NoError(err)
			pub, err := set.JSONPublic(t.Context())
			r.NoError(err)

			mux, err := newMux(&tc.opts, set)
			if tc.err != "" {
				a.Nil(set)
				r.EqualError(err, tc.err)
				return
			}

			// Test fetching the JWKs.
			req := httptest.NewRequestWithContext(
				t.Context(), http.MethodGet, "/.well-known/jwks.json", nil,
			)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			resp := w.Result()
			a.Equal(http.StatusOK, resp.StatusCode)
			a.Equal(resp.Header.Get("Content-Type"), "application/json")
			body, err := io.ReadAll(resp.Body)
			r.NoError(err)
			a.JSONEq(string(pub), string(body))
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
		kid  string
		form url.Values
		opts Options
	}{
		{
			test: "basic",
			form: url.Values{"username": []string{"theory"}},
			opts: Options{ExpireAfter: time.Hour * 24},
		},
		{
			test: "customized",
			form: url.Values{"username": []string{"❤️ & 🚀"}},
			opts: Options{
				Issuer:      "test",
				Audience:    "everyone",
				ExpireAfter: time.Hour,
			},
		},
	} {
		t.Run(tc.test, func(t *testing.T) {
			t.Parallel()
			a := assert.New(t)
			r := require.New(t)

			// Create a key.
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			r.NoError(err)
			key, err := jwkset.NewJWKFromKey(priv, jwkset.JWKOptions{})
			r.NoError(err)

			str, err := makeJWT(tc.form, tc.kid, key, &tc.opts)
			r.NoError(err)
			a.NotEmpty(str)

			tok, err := jwt.Parse(str, func(t *jwt.Token) (any, error) {
				return &priv.PublicKey, nil
			})
			r.NoError(err)
			a.NotNil(tok)

			// KID should be set.
			a.Equal(tc.kid, tok.Header[jwkset.HeaderKID])

			// Compare claims;
			str, err = tok.Claims.GetIssuer()
			r.NoError(err)
			a.Equal(tc.opts.Issuer, str)

			str, err = tok.Claims.GetSubject()
			r.NoError(err)
			a.Equal(tc.form.Get("username"), str)

			iat, err := tok.Claims.GetIssuedAt()
			r.NoError(err)
			a.WithinRange(iat.Time, start, time.Now())

			exp, err := tok.Claims.GetExpirationTime()
			r.NoError(err)
			a.Equal(iat.Add(tc.opts.ExpireAfter), exp.Time)

			aud, err := tok.Claims.GetAudience()
			r.NoError(err)
			if tc.opts.Audience == "" {
				a.Nil(aud)
			} else {
				a.Equal(jwt.ClaimStrings{tc.opts.Audience}, aud)
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

			req := httptest.NewRequestWithContext(
				t.Context(), http.MethodPost, "/",
				strings.NewReader(tc.form.Encode()),
			)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
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

			// Should hav error response.
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
