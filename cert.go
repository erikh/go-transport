package transport

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
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
	crl     *pkix.CertificateList

	certBytes []byte
}

// Verify verifies the certificate against the CA. if a CRL is supplied,
// ensures this cert is not in the CRL's serial numbers list.
func (c *Cert) Verify() bool {
	if c.ca == nil {
		return false
	}

	result := c.cert.CheckSignatureFrom(c.ca.cert) == nil
	if c.crl != nil {
		for _, cert := range c.crl.TBSCertList.RevokedCertificates {
			if cert.SerialNumber.Cmp(c.cert.SerialNumber) == 0 {
				return false
			}
		}
	}

	return result
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

// LoadCert loads the filenames provided into a *Cert. If you do not wish to
// leverage a CRL, just pass an empty string.
func LoadCert(cacert, certfile, keyfile, crlfile string) (*Cert, error) {
	var (
		ca  *Cert
		err error
	)

	if cacert != "" {
		ca, err = readCert(cacert, nil)
		if err != nil {
			return nil, errors.Wrap(err, cacert)
		}
	}

	cert, err := readCert(certfile, ca)
	if err != nil {
		return nil, errors.Wrap(err, certfile)
	}

	if err := cert.readKey(keyfile); err != nil {
		return nil, errors.Wrap(err, keyfile)
	}

	if crlfile != "" {
		content, err := ioutil.ReadFile(crlfile)
		if err != nil {
			return nil, errors.Wrap(err, crlfile)
		}

		crl, err := x509.ParseCRL(content)
		if err != nil {
			return nil, errors.Wrap(err, crlfile)
		}

		cert.crl = crl
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
