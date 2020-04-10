package transport

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"io/ioutil"
	"net"
	"strings"

	"github.com/pkg/errors"
)

// Cert is the encapsulation of a client or server certificate.
type Cert struct {
	ca *Cert

	dnsNames []string
	ips      []net.IP

	privkey crypto.PrivateKey
	pubkey  crypto.PublicKey
	cert    *x509.Certificate
	crl     *pkix.CertificateList

	certBytes []byte
}

func (c *Cert) verifyPeer(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if c.crl == nil {
		return nil
	}

	for _, outer := range verifiedChains {
		for _, inner := range outer {
			for _, cert := range c.crl.TBSCertList.RevokedCertificates {
				if cert.SerialNumber.Cmp(inner.SerialNumber) == 0 {
					return errors.New("certificate has been revoked")
				}
			}
		}
	}

	return nil
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

	switch {
	case strings.Contains(block.Type, "EC PRIVATE KEY"):
		var err error
		c.privkey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return errors.Wrap(err, "Could not parse EC private key")
		}
	case strings.Contains(block.Type, "RSA PRIVATE KEY"):
		var err error
		c.privkey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return errors.Wrap(err, "Could not parse RSA private key")
		}
	default:
		var err error
		c.privkey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return errors.Errorf("SEC1 format error: %v", err)
		}
	}

	switch priv := c.privkey.(type) {
	case *ecdsa.PrivateKey:
		c.pubkey = priv.Public()
	case *rsa.PrivateKey:
		c.pubkey = priv.Public()
	default:
		return errors.Errorf("Private key type (%T) was invalid", priv)
	}
	// FIXME
	return nil
}

// writeCert writes a certificate to the writer.
func (c *Cert) writeCert(writer io.Writer) error {
	return pem.Encode(writer, &pem.Block{Type: "CERTIFICATE", Bytes: c.certBytes})
}

// WriteKey writes the private key for the cert to the writer.
func (c *Cert) writeKey(writer io.Writer) error {
	bytes, err := x509.MarshalPKCS8PrivateKey(c.privkey)
	if err != nil {
		return err
	}
	return pem.Encode(writer, &pem.Block{Type: "PRIVATE KEY", Bytes: bytes})
}
