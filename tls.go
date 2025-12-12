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
		bundle, err := selfSigned()
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
		if err = os.WriteFile(file, bundle.CA, 0o666); err != nil {
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

func selfSigned() (*TLSBundle, error) {
	// Set up a subject shared by the CA and certs.
	sub := pkix.Name{
		Organization:  []string{"Hamilton Grange"},
		Country:       []string{"US"},
		Province:      []string{"NY"},
		Locality:      []string{"New York"},
		StreetAddress: []string{"414 West 141st Street"},
		PostalCode:    []string{"10031"},
	}

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
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Create and sign the CA with the public key.
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
	}

	// PEM-encode the cert.
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

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
		IPAddresses:  []net.IP{net.IPv4(local, 0, 0, 1), net.IPv6loopback},
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
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
	}

	// PEM-encode the cert.
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// Create and PEM-encode the key.
	x509Bytes, err := x509.MarshalECPrivateKey(certPrivKey)
	if err != nil {
		return nil, err
	}
	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: x509Bytes,
	})

	// All set.
	return &TLSBundle{CA: caPEM.Bytes(), Cert: certPEM.Bytes(), Key: certPrivKeyPEM.Bytes()}, nil
}
