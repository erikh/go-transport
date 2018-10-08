// Package transport implements basic TLS-backed transports. These transports
// can create both clients and servers; and if the cert is omitted, they will
// magically transform into plain connections. Be careful with nil pointers!
// The goal is to provide safe, common functionality from the crypto/tls,
// net/http and net packages based on modern practices for secure connectivity
// at the cost of the flexibility these packages provide.
//
// transport includes HTTP and TCP functionality, as well as a certificate
// utility framework that sits on top of most of the crypto, pki and x509
// packages.
//
// Please note that there are many constraints in the system as of now:
//
// * only ecdsa keys are supported
//
// * CRLs are supported; but you must manually check them (we also have
// whitelisting of serial numbers if you'd prefer to avoid CRLs entirely)
//
// * You must use a CA that can be verified; this means that self-signed certs
// are largely out. Build a real CA instead.
//
package transport

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
)

type tlsInfo struct {
	insecure bool
	cert     *Cert
	tlsCert  tls.Certificate
	pool     *x509.CertPool
}

// HTTP is the basic implementation of a HTTP transport with security features.
// See NewHTTP() for more.
type HTTP struct {
	*tlsInfo
}

// TCP is the basic implementation of a TLS-enabled TCP connection. See NewTCP() for more.
type TCP struct {
	*tlsInfo
}

func mktlsInfo(cert *Cert) (*tlsInfo, error) {
	pool := x509.NewCertPool()
	if cert.ca == nil {
		return nil, errors.New("missing CA during secure transport initialization")
	}
	pool.AddCert(cert.ca.cert)

	certout := bytes.NewBuffer(nil)
	keyout := bytes.NewBuffer(nil)

	if err := cert.writeCert(certout); err != nil {
		return nil, err
	}

	if err := cert.writeKey(keyout); err != nil {
		return nil, err
	}

	tlscert, err := tls.X509KeyPair(certout.Bytes(), keyout.Bytes())
	return &tlsInfo{cert: cert, pool: pool, tlsCert: tlscert}, err
}

// NewHTTP provides a new HTTP transport with a provided cert. The cert should
// have a loaded CA. If the cert is nil, insecure connections will be created.
func NewHTTP(cert *Cert) (*HTTP, error) {
	if cert == nil {
		return &HTTP{&tlsInfo{insecure: true}}, nil
	}

	tlsInfo, err := mktlsInfo(cert)
	return &HTTP{tlsInfo}, err
}

func (t tlsInfo) tlsConfig() *tls.Config {
	if t.insecure {
		return nil
	}

	return &tls.Config{
		RootCAs:      t.pool,
		ClientCAs:    t.pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{t.tlsCert},
	}
}

// Server creates a HTTP server with CA and client cert verification. If the
// cert provided is nil, creates an insecure connection.
func (h *HTTP) Server(host string, handler http.Handler) (*http.Server, net.Listener, error) {
	var (
		l         net.Listener
		err       error
		tlsConfig *tls.Config
	)

	tcpTransport := &TCP{h.tlsInfo}
	l, err = tcpTransport.Listen("tcp", host)
	tlsConfig = h.tlsConfig()

	return &http.Server{
		Addr:      host,
		Handler:   handler,
		TLSConfig: tlsConfig,
	}, l, err
}

// Client provides a client with a transport configured to use TLS
// certificate authentication.
func (h *HTTP) Client(t *http.Transport) *http.Client {
	t.TLSClientConfig = h.tlsConfig()
	return &http.Client{Transport: t}
}

// NewTCP sets up a new TCP transport. If a cert is provided, these will be
// tls-encrypted transports; otherwise they will be insecure.
func NewTCP(cert *Cert) (*TCP, error) {
	if cert == nil {
		return &TCP{&tlsInfo{insecure: true}}, nil
	}

	tlsInfo, err := mktlsInfo(cert)
	return &TCP{tlsInfo}, err
}

// Dial engages with the server as a raw TCP connection. If the cert is passed
// as nil, does a straight net.Dial. Returns an io.ReadWriteCloser, as
// *tls.Conn and net.Conn are incompatible type-wise.
func (t *TCP) Dial(network, addr string) (io.ReadWriteCloser, error) {
	if t.insecure {
		return net.Dial(network, addr)
	}

	return tls.Dial(network, addr, t.tlsConfig())
}

// Listen listens as a secure TCP server. If the cert is passed as nil, does a
// straight net.Listen.
func (t *TCP) Listen(network, addr string) (net.Listener, error) {
	if t.insecure {
		return net.Listen(network, addr)
	}

	return tls.Listen(network, addr, t.tlsConfig())
}
