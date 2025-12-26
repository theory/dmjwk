package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	filePerms = 0o600
)

func tlsConfig(opts *Options) (*tls.Config, error) {
	var (
		cert tls.Certificate
		err  error
	)

	// Load user-provided key pair.
	if opts.KeyPath != "" {
		cert, err = tls.LoadX509KeyPair(
			filepath.Clean(filepath.Join(opts.ConfigDir, opts.CertPath)),
			filepath.Clean(filepath.Join(opts.ConfigDir, opts.KeyPath)),
		)
		if err != nil {
			return nil, err
		}
	} else {
		// Create a CA cert and key pair.
		bundle, err := selfSigned(opts)
		if err != nil {
			return nil, err
		}

		// Parse the key pair.
		cert, err = tls.X509KeyPair(bundle.Cert, bundle.Key)
		if err != nil {
			return nil, err
		}

		// Write out the CA cert.
		file := filepath.Clean(filepath.Join(opts.ConfigDir, "ca.pem"))
		if err = os.WriteFile(file, bundle.CA, filePerms); err != nil {
			return nil, err
		}
	}

	// All good.
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}, nil
}

type TLSBundle struct {
	// CA contains the CA [KeyPair] object.
	CA []byte

	Cert []byte

	Key []byte
}

func selfSigned(opts *Options) (*TLSBundle, error) {
	// Set up a subject shared by the CA and certs.
	sub := pkix.Name{Organization: []string{"dmjwk Holdings, Inc."}}

	// Create a CA template with a random serial number.
	sn, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt32))
	if err != nil {
		return nil, err
	}

	const lifetimeDays = 30
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               sub,
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, lifetimeDays),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Create the key pair.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Create and sign the CA with the public key.
	// Generate the self-signed CA private key and public certificate.
	caPEM, _, err := newKeyPair(caKey, caKey, ca, ca, false)
	if err != nil {
		return nil, err
	}

	// Create the server certificate with a random serial number.
	// Give the cert a random serial number.
	sn, err = rand.Int(rand.Reader, big.NewInt(math.MaxInt32))
	if err != nil {
		return nil, err
	}

	const local = 127
	cert := &x509.Certificate{
		Subject:      sub,
		SerialNumber: sn,
		SubjectKeyId: []byte(randID()),
		IPAddresses:  []net.IP{net.IPv4(local, 0, 0, 1), net.IPv4(0, 0, 0, 0), net.IPv6loopback},
		DNSNames:     opts.dnsNames(),
		NotBefore:    now,
		NotAfter:     now.AddDate(0, 0, lifetimeDays),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// Create the key pair.
	certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Create and sign the certificate with the public key.
	certPEM, certPrivKeyPEM, err := newKeyPair(caKey, certPrivKey, ca, cert, true)
	if err != nil {
		return nil, err
	}

	// All set.
	return &TLSBundle{CA: caPEM, Cert: certPEM, Key: certPrivKeyPEM}, nil
}

func newKeyPair(caKey, certKey *ecdsa.PrivateKey, ca, cert *x509.Certificate, mkPriv bool) ([]byte, []byte, error) {
	// Sign the public key with the caKey and generate an x509 cert.
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	// PEM-encode the cert.
	certPEM := new(bytes.Buffer)
	if err := pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		return nil, nil, err
	}

	if !mkPriv {
		return certPEM.Bytes(), nil, nil
	}

	// Generate and PEM-encode the private key.
	x509Bytes, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := new(bytes.Buffer)
	if err := pem.Encode(keyPEM, &pem.Block{Type: "EC PRIVATE KEY", Bytes: x509Bytes}); err != nil {
		return nil, nil, err
	}

	// Return the key pair.
	return certPEM.Bytes(), keyPEM.Bytes(), nil
}
