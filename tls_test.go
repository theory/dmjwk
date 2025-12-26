package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelfSigned(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	r := require.New(t)

	bundle, err := selfSigned()
	r.NoError(err)
	a.NotNil(bundle.CA)
	a.NotNil(bundle.Cert)
	a.NotNil(bundle.Key)

	// Parse the key pair into a tls config.
	cert, err := tls.X509KeyPair(bundle.Cert, bundle.Key)
	r.NoError(err)

	// Make sure it all works.
	checkTLSConfig(t, bundle.CA, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
}

func TestTLSConfig(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	r := require.New(t)
	tmp := t.TempDir()

	// Test missing files.
	cfg, err := tlsConfig(&Options{ConfigDir: tmp, KeyPath: "nonesuch"})
	a.Zero(cfg)
	r.ErrorContains(err, "read")

	// Try no files.
	cfg, err = tlsConfig(&Options{ConfigDir: tmp})
	r.NoError(err)
	a.NotNil(cfg)

	// Should have written out ca.pem.
	caBytes, err := os.ReadFile(filepath.Clean(filepath.Join(tmp, "ca.pem")))
	r.NoError(err)

	// Make sure it all works.
	checkTLSConfig(t, caBytes, cfg)

	// Write out key and cert files.
	bundle, err := selfSigned()
	r.NoError(err)
	keyFile := filepath.Join(tmp, "key.pem")
	certFile := filepath.Join(tmp, "cert.pem")
	r.NoError(os.WriteFile(keyFile, bundle.Key, filePerms))
	r.NoError(os.WriteFile(certFile, bundle.Cert, filePerms))

	// Point to them.
	cfg, err = tlsConfig(&Options{
		ConfigDir: tmp, KeyPath: "key.pem", CertPath: "cert.pem",
	})
	r.NoError(err)

	// Make sure they work!
	checkTLSConfig(t, bundle.CA, cfg)
}

func checkTLSConfig(t *testing.T, ca []byte, cfg *tls.Config) {
	t.Helper()
	a := assert.New(t)
	r := require.New(t)

	// Configure an HTTP server.
	server := httptest.NewUnstartedServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, "success!")
		}),
	)
	server.TLS = cfg
	server.StartTLS()
	defer server.Close()

	// Setup a client with the CA cert.
	pool := x509.NewCertPool()
	a.True(pool.AppendCertsFromPEM(ca))
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	// Test request.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
	r.NoError(err)
	resp, err := client.Do(req)
	r.NoError(err)
	body, err := io.ReadAll(resp.Body)
	r.NoError(err)
	r.NoError(resp.Body.Close())
	a.Equal("success!", string(body))
}
