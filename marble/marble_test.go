package marble

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetServerTLSConfig(t *testing.T) {
	defer resetEnv()
	assert := assert.New(t)
	require := require.New(t)

	// Get server TLS config
	setupTest(require)
	tlsConfig, err := GetServerTLSConfig()
	require.NoError(err)
	assert.NotNil(tlsConfig)

	// Check client CA certificate
	clientCAPool := tlsConfig.ClientCAs
	clientCAPoolSubjects := clientCAPool.Subjects()

	// x509 cert pools don't allow to extract certificates inside them. How great is that? So we gotta extract the ASN.1 subject and work with it.
	// This was taken (and slightly modified) from: https://github.com/golang/go/issues/26614#issuecomment-613640345
	var rdnSequence pkix.RDNSequence
	_, err = asn1.Unmarshal(clientCAPoolSubjects[0], &rdnSequence)
	require.NoError(err)
	var name pkix.Name
	name.FillFromRDNSequence(&rdnSequence)
	commonName := name.CommonName

	assert.Equal("Test CA", commonName)

	// Check leaf certificate
	certificates := tlsConfig.Certificates
	rawCertificate := certificates[0].Certificate[0]
	x509Cert, err := x509.ParseCertificate(rawCertificate)
	require.NoError(err)
	assert.Equal(big.NewInt(1337), x509Cert.SerialNumber)
	assert.Equal("Test Leaf", x509Cert.Subject.CommonName)

	// Check ClientAuth value
	assert.Equal(tls.RequireAndVerifyClientCert, tlsConfig.ClientAuth)
}

func TestGetClientTLSConfig(t *testing.T) {
	defer resetEnv()
	assert := assert.New(t)
	require := require.New(t)

	// Get client TLS config
	setupTest(require)
	tlsConfig, err := GetClientTLSConfig()
	require.NoError(err)
	assert.NotNil(tlsConfig)

	// Check root certificate
	rootCertPool := tlsConfig.RootCAs
	rootCertPoolSubjects := rootCertPool.Subjects()

	// x509 cert pools don't allow to extract certificates inside them. How great is that? So we gotta extract the ASN.1 subject and work with it.
	// This was taken (and slightly modified) from: https://github.com/golang/go/issues/26614#issuecomment-613640345
	var rdnSequence pkix.RDNSequence
	_, err = asn1.Unmarshal(rootCertPoolSubjects[0], &rdnSequence)
	require.NoError(err)
	var name pkix.Name
	name.FillFromRDNSequence(&rdnSequence)
	commonName := name.CommonName

	assert.Equal("Test CA", commonName)

	// Check leaf certificate
	certificates := tlsConfig.Certificates
	rawCertificate := certificates[0].Certificate[0]
	x509Cert, err := x509.ParseCertificate(rawCertificate)
	require.NoError(err)
	assert.Equal(big.NewInt(1337), x509Cert.SerialNumber)
	assert.Equal("Test Leaf", x509Cert.Subject.CommonName)
}

func TestGarbageEnviromentVars(t *testing.T) {
	defer resetEnv()
	assert := assert.New(t)

	// Set environment variables
	os.Setenv("MARBLE_PREDEFINED_ROOT_CA", "this")
	os.Setenv("MARBLE_PREDEFINED_MARBLE_CERT", "is")
	os.Setenv("MARBLE_PREDEFINED_PRIVATE_KEY", "some serious garbage")

	// This should fail
	tlsConfig, err := GetServerTLSConfig()
	assert.Error(err)
	assert.Nil(tlsConfig)
}

func TestMissingEnvironmentVars(t *testing.T) {
	assert := assert.New(t)
	tlsConfig, err := GetClientTLSConfig()

	assert.Error(err)
	assert.Nil(tlsConfig)
}

func setupTest(require *require.Assertions) {
	// Generate keys
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(err)
	privKey, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(err)

	// Create some demo CA certificate
	templateCa := x509.Certificate{
		SerialNumber: big.NewInt(42),
		IsCA:         true,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
	}

	// Create some demo leaf certificate
	templateLeaf := x509.Certificate{
		SerialNumber: big.NewInt(1337),
		IsCA:         false,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
		Subject: pkix.Name{
			CommonName: "Test Leaf",
		},
	}

	// Create test CA cert
	certCaRaw, err := x509.CreateCertificate(rand.Reader, &templateCa, &templateCa, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	certCa, err := x509.ParseCertificate(certCaRaw)
	if err != nil {
		panic(err)
	}

	// Create test leaf cert
	certLeafRaw, err := x509.CreateCertificate(rand.Reader, &templateLeaf, certCa, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	certLeaf, err := x509.ParseCertificate(certLeafRaw)
	if err != nil {
		panic(err)
	}

	// Convert them to PEM
	caCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certCa.Raw})
	leafCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certLeaf.Raw})
	privKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKey})

	// Set environment variables
	os.Setenv("MARBLE_PREDEFINED_ROOT_CA", string(caCertPem))
	os.Setenv("MARBLE_PREDEFINED_MARBLE_CERT", string(leafCertPem))
	os.Setenv("MARBLE_PREDEFINED_PRIVATE_KEY", string(privKeyPem))
}

func resetEnv() {
	// Clean up used environment variables, otherwise they stay set!
	os.Unsetenv("MARBLE_PREDEFINED_ROOT_CA")
	os.Unsetenv("MARBLE_PREDEFINED_MARBLE_CERT")
	os.Unsetenv("MARBLE_PREDEFINED_PRIVATE_KEY")
}
