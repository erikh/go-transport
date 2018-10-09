package transport

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/ioutil"
	"net"

	"github.com/pkg/errors"
)

// Cert is the encapsulation of a client or server certificate.
type Cert struct {
	ca *Cert

	dnsNames []string
	ips      []net.IP

	privkey *ecdsa.PrivateKey
	pubkey  ecdsa.PublicKey
	cert    *x509.Certificate

	certBytes []byte
}

// Verify verifies the certificate against the CA.
func (c *Cert) Verify() bool {
	if c.ca == nil {
		return false
	}

	return c.cert.CheckSignatureFrom(c.ca.cert) == nil
}

// IsClient returns true if this is a client cert.
func (c *Cert) IsClient() bool {
	for _, usage := range c.cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			return true
		}
	}

	return false
}

// IsServer returns true if this is a server cert.
func (c *Cert) IsServer() bool {
	for _, usage := range c.cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			return true
		}
	}

	return false
}

// LoadCert loads the filenames provided into a *Cert.
func LoadCert(cacert, certfile, keyfile string) (*Cert, error) {
	ca, err := readCert(cacert, nil)
	if err != nil {
		return nil, errors.Wrap(err, cacert)
	}

	cert, err := readCert(certfile, ca)
	if err != nil {
		return nil, errors.Wrap(err, certfile)
	}

	if err := cert.readKey(keyfile); err != nil {
		return nil, errors.Wrap(err, keyfile)
	}

	return cert, nil
}

// ReadCert reads from a reader and returns a *Cert. Note that the private key
// must still be read for most *Cert operations to be useful.
func readCert(filename string, ca *Cert) (*Cert, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(content)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &Cert{
		ca:        ca,
		certBytes: block.Bytes,
		cert:      cert,
	}, nil
}

func (c *Cert) readKey(filename string) error {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(content)

	c.privkey, err = x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	c.pubkey = *c.privkey.Public().(*ecdsa.PublicKey)

	return nil
}

// writeCert writes a certificate to the writer.
func (c *Cert) writeCert(writer io.Writer) error {
	return pem.Encode(writer, &pem.Block{Type: "CERTIFICATE", Bytes: c.certBytes})
}

// WriteKey writes the private key for the cert to the writer.
func (c *Cert) writeKey(writer io.Writer) error {
	bytes, err := x509.MarshalECPrivateKey(c.privkey)
	if err != nil {
		return err
	}
	return pem.Encode(writer, &pem.Block{Type: "EC PRIVATE KEY", Bytes: bytes})
}
