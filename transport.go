// Package transport implements basic TLS-backed transports. These transports can
// create both clients and servers that can auth via client cert; and if the cert
// is omitted, they will magically transform into plain connections. Be careful
// with nil pointers!  The goal is to provide safe, common functionality from the
// crypto/tls, net/http and net packages based on modern practices for secure
// connectivity at the cost of the flexibility these packages provide.
//
// transport includes HTTP and TCP functionality, as well as a certificate
// utility framework that sits on top of most of the crypto, pki and x509
// packages.
//
// Additionally, it resolves CRLs in a meaningful way at the time of connect, if a
// CRL is provided.
//
// Please note that there are many constraints in the system as of now:
//
// * largely only situations where client certs are needed is where this library
// excels; I hope to change that in the future but this is my current
// use-case...  So until that changes, this library will likely not grow much.
// * only ecdsa keys are supported
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

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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

// TCPTLSClient is the basic implementation of a TLS-enabled TCP connection. See NewTCPTLS() for more.
type TCPTLSClient interface {
	io.ReadWriteCloser
}

// TCPTLSServer functions like a net.Listener but may or may not contain
// security features due to the presence of a cert; interface is the same for
// both.
type TCPTLSServer struct {
	*tlsInfo
	net.Listener
}

// TCPConn is a plain TCP connection.
type TCPConn struct {
	*tlsInfo
	net.Conn
}

// TLSConn is a tls-secured TCP connection.
type TLSConn struct {
	*tlsInfo
	*tls.Conn
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
		VerifyPeerCertificate: t.cert.verifyPeer,
		RootCAs:               t.pool,
		ClientCAs:             t.pool,
		ClientAuth:            tls.RequireAndVerifyClientCert,
		Certificates:          []tls.Certificate{t.tlsCert},
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

	l, err = Listen(h.cert, "tcp", host)
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
	if t == nil {
		t = &http.Transport{}
	}
	t.TLSClientConfig = h.tlsConfig()
	return &http.Client{Transport: t}
}

// Dial dials the tcp listener on addr and optionally wraps it in tls if a cert
// is provided.
func Dial(cert *Cert, network, addr string) (TCPTLSClient, error) {
	if cert == nil {
		conn, err := net.Dial(network, addr)
		if err != nil {
			return nil, err
		}
		return &TCPConn{tlsInfo: &tlsInfo{insecure: true}, Conn: conn}, nil
	}

	tlsInfo, err := mktlsInfo(cert)
	if err != nil {
		return nil, err
	}

	conn, err := tls.Dial(network, addr, tlsInfo.tlsConfig())
	if err != nil {
		return nil, err
	}

	return &TLSConn{Conn: conn, tlsInfo: tlsInfo}, nil
}

// Listen listens as a secure TCP server. If the cert is passed as nil, does a
// straight net.Listen.
func Listen(cert *Cert, network, addr string) (net.Listener, error) {
	if cert == nil {
		l, err := net.Listen(network, addr)
		if err != nil {
			return nil, err
		}

		return &TCPTLSServer{Listener: l, tlsInfo: &tlsInfo{insecure: true}}, nil
	}

	t, err := mktlsInfo(cert)
	if err != nil {
		return nil, err
	}

	l, err := tls.Listen(network, addr, t.tlsConfig())
	if err != nil {
		return nil, err
	}

	return &TCPTLSServer{Listener: l, tlsInfo: t}, nil
}

// GRPCDial dials a GRPC service with the Client configured to the cert.
func GRPCDial(cert *Cert, addr string, options ...grpc.DialOption) (*grpc.ClientConn, error) {
	if cert != nil {
		t, err := mktlsInfo(cert)
		if err != nil {
			return nil, err
		}
		options = append(options, grpc.WithTransportCredentials(credentials.NewTLS(t.tlsConfig())))
	} else {
		options = append(options, grpc.WithInsecure())
	}

	return grpc.Dial(addr, options...)
}
