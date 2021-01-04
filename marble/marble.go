// Package marble provides commonly used functionalities for Marblerun Marbles.
package marble

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// MarbleEnvironmentCertificate contains the name of the environment variable holding a marble-specifc PEM encoded certificate
const MarbleEnvironmentCertificate = "MARBLE_PREDEFINED_MARBLE_CERTIFICATE"

// MarbleEnvironmentRootCA contains the name of the environment variable holding a PEM encoded root certificate
const MarbleEnvironmentRootCA = "MARBLE_PREDEFINED_ROOT_CA"

// MarbleEnvironmentPrivateKey contains the name of the environment variable holding a PEM encoded private key belonging to the marble-specific certificate
const MarbleEnvironmentPrivateKey = "MARBLE_PREDEFINED_PRIVATE_KEY"

// GetTLSConfig provides a preconfigured TLS config for marbles, using the Marblerun Coordinator as trust anchor
func GetTLSConfig(verifyClientCerts bool) (*tls.Config, error) {
	tlsCert, roots, err := generateFromEnv()
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		RootCAs:      roots,
		Certificates: []tls.Certificate{tlsCert},
	}

	if verifyClientCerts {
		tlsConfig.ClientCAs = roots
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsConfig, nil
}

func getByteEnv(name string) ([]byte, error) {
	value := os.Getenv(name)
	if len(value) == 0 {
		return nil, fmt.Errorf("environment variable not set: %s", name)
	}
	return []byte(value), nil
}

func generateFromEnv() (tls.Certificate, *x509.CertPool, error) {
	cert, err := getByteEnv(MarbleEnvironmentCertificate)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	rootCA, err := getByteEnv(MarbleEnvironmentRootCA)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	privk, err := getByteEnv(MarbleEnvironmentPrivateKey)
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
