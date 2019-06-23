package transport

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"time"

	. "gopkg.in/check.v1"
)

var certGenerators = []certGenerator{&certGen{}, &mkCert{}}

func revoke(dir string, c *Cert, ca *Cert, crl *pkix.CertificateList) (string, error) {
	rcs := crl.TBSCertList.RevokedCertificates
	rc := pkix.RevokedCertificate{
		SerialNumber:   c.cert.SerialNumber,
		RevocationTime: time.Now(),
	}

	rcs = append(rcs, rc)

	derBytes, err := ca.cert.CreateCRL(rand.Reader, ca.privkey, rcs, time.Now(), time.Now().Add(24*time.Hour*365))
	if err != nil {
		return "", err
	}

	f, err := ioutil.TempFile(dir, "crl-")
	if err != nil {
		return "", err
	}
	defer f.Close()

	return f.Name(), pem.Encode(f, &pem.Block{Type: "X509 CRL", Bytes: derBytes})
}

func tempFile(dir, prefix string) (string, error) {
	f, err := ioutil.TempFile(dir, prefix)
	if err != nil {
		return "", err
	}
	f.Close()

	return f.Name(), nil
}

type certGenerator interface {
	CertPair(dir, caCert, caKey string, client bool) (string, string, error)
	CACertPair(dir string) (string, string, error)
}

type mkCert struct{}

func (c *mkCert) String() string {
	return "mkCert"
}

func (c *mkCert) CertPair(dir, caCert, caKey string, client bool) (string, string, error) {
	cert, err := tempFile(dir, "cert-")
	if err != nil {
		return "", "", err
	}

	key, err := tempFile(dir, "key-")
	if err != nil {
		return "", "", err
	}

	args := []string{
		"--ecdsa",
		"--cert-file", cert,
		"--key-file", key,
		"localhost",
	}

	if client {
		args = append([]string{"--client"}, args...)
	}

	cmd := exec.Command("mkcert", args...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("CAROOT=%s", dir))

	return cert, key, cmd.Run()
}

func (c *mkCert) CACertPair(dir string) (string, string, error) {
	cmd := exec.Command("mkcert", "--install", "--ecdsa")
	cmd.Env = append(os.Environ(), fmt.Sprintf("CAROOT=%s", dir))

	return path.Join(dir, "rootCA.pem"), path.Join(dir, "rootCA-key.pem"), cmd.Run()
}

type certGen struct{}

func (c *certGen) String() string {
	return "certGen"
}

func (c *certGen) CertPair(dir, caCert, caKey string, client bool) (string, string, error) {
	cert, err := tempFile(dir, "cert-")
	if err != nil {
		return "", "", err
	}

	key, err := tempFile(dir, "key-")
	if err != nil {
		return "", "", err
	}

	args := []string{
		"-sign-cert", caCert,
		"-sign-key", caKey,
		"-out-cert", cert,
		"-out-key", key,
		"-host", "localhost",
	}

	if client {
		args = append(args, "-client")
	}

	return cert, key, exec.Command("certgen", args...).Run()
}

func (c *certGen) CACertPair(dir string) (string, string, error) {
	caCert, err := tempFile(dir, "ca-cert-")
	if err != nil {
		return "", "", err
	}

	caKey, err := tempFile(dir, "ca-key-")
	if err != nil {
		return "", "", err
	}

	return caCert, caKey, exec.Command("certgen", "-ca", "-out-cert", caCert, "-out-key", caKey).Run()
}

func (ts *transportSuite) TestCert(c *C) {
	dir, err := ioutil.TempDir("", "go-transport-")
	c.Assert(err, IsNil)
	defer os.RemoveAll(dir)

	for _, cg := range certGenerators {
		os.RemoveAll(dir)
		os.MkdirAll(dir, 0700)
		caCert, caKey, err := cg.CACertPair(dir)
		c.Assert(err, IsNil)

		cert, key, err := cg.CertPair(dir, caCert, caKey, false)
		c.Assert(err, IsNil)

		ourCert, err := LoadCert(caCert, cert, key, "")
		c.Assert(err, IsNil)
		c.Assert(ourCert.Verify(), Equals, true)

		c.Assert(ourCert.IsServer(), Equals, true)

		client, clientKey, err := cg.CertPair(dir, caCert, caKey, true)
		c.Assert(err, IsNil)

		clientCert, err := LoadCert(caCert, client, clientKey, "")
		c.Assert(err, IsNil)
		c.Assert(clientCert.Verify(), Equals, true)
		c.Assert(clientCert.IsClient(), Equals, true)

		ca, err := LoadCert("", caCert, caKey, "")
		c.Assert(err, IsNil)

		crlName, err := revoke(dir, ourCert, ca, &pkix.CertificateList{})
		c.Assert(err, IsNil)

		ourCert, err = LoadCert(caCert, cert, key, crlName)
		c.Assert(err, IsNil)
		c.Assert(ourCert.Verify(), Equals, false)

		crlName, err = revoke(dir, clientCert, ca, ourCert.crl)
		c.Assert(err, IsNil)

		clientCert, err = LoadCert(caCert, client, clientKey, crlName)
		c.Assert(err, IsNil)
		c.Assert(clientCert.Verify(), Equals, false)

		c.Assert(os.MkdirAll(path.Join(dir, "alternate"), 0700), IsNil)
		caCert2, caKey, err := cg.CACertPair(path.Join(dir, "alternate"))
		c.Assert(err, IsNil)

		cert2, err := LoadCert(caCert2, client, clientKey, "")
		c.Assert(err, IsNil)
		c.Assert(cert2.Verify(), Equals, false)

		cert2, err = LoadCert(caCert2, cert, key, "")
		c.Assert(err, IsNil)
		c.Assert(cert2.Verify(), Equals, false)
	}
}
