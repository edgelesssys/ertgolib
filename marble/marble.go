// Package marble provides commonly used functionalities for Marblerun Marbles.
package marble

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// GetServerTLSConfig provides a preconfigured server TLS config for the communication between marbles.
func GetServerTLSConfig() (*tls.Config, error) {
	tlsCert, roots, err := generateFromEnv()
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		ClientCAs:    roots,
		Certificates: []tls.Certificate{tlsCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	return tlsConfig, nil
}

// GetClientTLSConfig provides a preconfigured client TLS config for the communication between marbles.
func GetClientTLSConfig() (*tls.Config, error) {
	tlsCert, roots, err := generateFromEnv()
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		RootCAs:      roots,
		Certificates: []tls.Certificate{tlsCert},
	}

	return tlsConfig, nil
}

func mustGetByteEnv(name string) ([]byte, error) {
	value := os.Getenv(name)
	if len(value) == 0 {
		return nil, fmt.Errorf("environment variable not set: %s", name)
	}
	return []byte(value), nil
}

func generateFromEnv() (tls.Certificate, *x509.CertPool, error) {
	cert, err := mustGetByteEnv("MARBLE_PREDEFINED_MARBLE_CERT")
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	rootCA, err := mustGetByteEnv("MARBLE_PREDEFINED_ROOT_CA")
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	privk, err := mustGetByteEnv("MARBLE_PREDEFINED_PRIVATE_KEY")
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootCA) {
		return tls.Certificate{}, nil, fmt.Errorf("cannot append rootCa to CertPool")
	}

	tlsCert, err := tls.X509KeyPair(cert, privk)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("cannot create TLS cert: %v", err)
	}

	return tlsCert, roots, nil
}
