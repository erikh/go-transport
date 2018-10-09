package transport

import (
	"crypto/x509/pkix"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	. "testing"

	. "gopkg.in/check.v1"
)

type transportSuite struct{}

var _ = Suite(&transportSuite{})

func TestTransport(t *T) {
	TestingT(t)
}

type successHandler struct{}

func (h *successHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "hello from go-transport")
}

func (ts *transportSuite) TestBasicHTTP(c *C) {
	dir, err := ioutil.TempDir("", "")
	c.Assert(err, IsNil)
	defer os.RemoveAll(dir)

	caFile, caKeyFile, err := caCertPair(dir)
	c.Assert(err, IsNil)

	certFile, keyFile, err := certPair(dir, caFile, caKeyFile, false)
	c.Assert(err, IsNil)

	clientFile, clientKeyFile, err := certPair(dir, caFile, caKeyFile, true)
	c.Assert(err, IsNil)

	cert, err := LoadCert(caFile, certFile, keyFile, "")
	c.Assert(err, IsNil)

	clientCert, err := LoadCert(caFile, clientFile, clientKeyFile, "")
	c.Assert(err, IsNil)

	server, err := NewHTTP(cert)
	c.Assert(err, IsNil)

	client, err := NewHTTP(clientCert)
	c.Assert(err, IsNil)

	s, l, err := server.Server("localhost:8000", &successHandler{})
	c.Assert(err, IsNil)
	go s.Serve(l)
	defer l.Close()

	resp, err := client.Client(nil).Get("https://localhost:8000")
	c.Assert(err, IsNil)
	c.Assert(resp.StatusCode, Equals, 200)
	content, err := ioutil.ReadAll(resp.Body)
	c.Assert(err, IsNil)
	c.Assert(string(content), Equals, "hello from go-transport")
}

func (ts *transportSuite) TestHTTPCRL(c *C) {
	dir, err := ioutil.TempDir("", "")
	c.Assert(err, IsNil)
	defer os.RemoveAll(dir)

	caFile, caKeyFile, err := caCertPair(dir)
	c.Assert(err, IsNil)

	certFile, keyFile, err := certPair(dir, caFile, caKeyFile, false)
	c.Assert(err, IsNil)

	clientFile, clientKeyFile, err := certPair(dir, caFile, caKeyFile, true)
	c.Assert(err, IsNil)

	clientFile2, clientKeyFile2, err := certPair(dir, caFile, caKeyFile, true)
	c.Assert(err, IsNil)

	clientCert, err := LoadCert(caFile, clientFile, clientKeyFile, "")
	c.Assert(err, IsNil)

	clientCert2, err := LoadCert(caFile, clientFile2, clientKeyFile2, "")
	c.Assert(err, IsNil)

	ca, err := LoadCert("", caFile, caKeyFile, "")
	c.Assert(err, IsNil)

	crlName, err := revoke(dir, clientCert, ca, &pkix.CertificateList{})
	c.Assert(err, IsNil)

	cert, err := LoadCert(caFile, certFile, keyFile, crlName)
	c.Assert(err, IsNil)

	server, err := NewHTTP(cert)
	c.Assert(err, IsNil)

	s, l, err := server.Server("localhost:8000", &successHandler{})
	c.Assert(err, IsNil)
	go s.Serve(l)
	defer l.Close()

	badClient, err := NewHTTP(clientCert)
	_, err = badClient.Client(nil).Get("https://localhost:8000")
	c.Assert(err, NotNil)

	goodClient, err := NewHTTP(clientCert2)
	resp, err := goodClient.Client(nil).Get("https://localhost:8000")
	c.Assert(err, IsNil)
	c.Assert(resp.StatusCode, Equals, 200)
	content, err := ioutil.ReadAll(resp.Body)
	c.Assert(err, IsNil)
	c.Assert(string(content), Equals, "hello from go-transport")
}
