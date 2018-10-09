package transport

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"os"
	"os/exec"
	"time"

	. "gopkg.in/check.v1"
)

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

func certPair(dir, caCert, caKey string, client bool) (string, string, error) {
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

func caCertPair(dir string) (string, string, error) {
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

	caCert, caKey, err := caCertPair(dir)
	c.Assert(err, IsNil)

	cert, key, err := certPair(dir, caCert, caKey, false)
	c.Assert(err, IsNil)

	ourCert, err := LoadCert(caCert, cert, key, "")
	c.Assert(err, IsNil)
	c.Assert(ourCert.Verify(), Equals, true)

	c.Assert(ourCert.IsServer(), Equals, true)
	c.Assert(ourCert.IsClient(), Equals, true)

	client, clientKey, err := certPair(dir, caCert, caKey, true)
	c.Assert(err, IsNil)

	clientCert, err := LoadCert(caCert, client, clientKey, "")
	c.Assert(err, IsNil)
	c.Assert(clientCert.Verify(), Equals, true)
	c.Assert(clientCert.IsClient(), Equals, true)
	c.Assert(clientCert.IsServer(), Equals, false)

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

	caCert2, caKey, err := caCertPair(dir)
	c.Assert(err, IsNil)

	cert2, err := LoadCert(caCert2, client, clientKey, "")
	c.Assert(err, IsNil)
	c.Assert(cert2.Verify(), Equals, false)

	cert2, err = LoadCert(caCert2, cert, key, "")
	c.Assert(err, IsNil)
	c.Assert(cert2.Verify(), Equals, false)
}
