// Copyright 2009 The Go Authors. All rights reserved.  Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.
//
// Modifications for the go-transport project (2018) by Erik Hollensbe;
// licensed with the same license provided with golang.

// +build nobuild

// XXX building with the default ignore tag causes a lot of problems outside of
// the golang test suite; so I changed it to something unique. -erikh

// go-transport note: This is a modification of the cert generation test code
// golang uses to generate the certs we need for our tests. This is in no way
// recommended for real-world use and will not build by default.

// Improvements:
// - ecdsa is now default with P256 curve (rsa code path is preserved; pass -rsa)
// - signing code for CAs
// - output to desired files
// - ability to generate client auth certs

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

var (
	host       = flag.String("host", "", "Comma-separated hostnames and IPs to generate a certificate for")
	validFrom  = flag.String("start-date", "", "Creation date formatted as Jan 1 15:04:05 2011")
	validFor   = flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
	isCA       = flag.Bool("ca", false, "whether this cert should be its own Certificate Authority")
	rsaKey     = flag.Bool("rsa", false, "Whether or not this should be an RSA key. The default is to generate ECDSA")
	rsaBits    = flag.Int("rsa-bits", 2048, "Size of RSA key to generate. Ignored if --ecdsa-curve is set")
	ecdsaCurve = flag.String("ecdsa-curve", "P256", "ECDSA curve to use to generate a key. Valid values are P224, P256 (recommended), P384, P521")
	isClient   = flag.Bool("client", false, "if set, this will be a client cert instead of a server cert")

	signCert = flag.String("sign-cert", "", "cert to sign this new cert with")
	signKey  = flag.String("sign-key", "", "key to sign this new cert with")
	outCert  = flag.String("out-cert", "cert.pem", "output cert to this filename")
	outKey   = flag.String("out-key", "cert.key", "output key to this filename")
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func mkCSR(template *x509.Certificate, priv interface{}) (*x509.CertificateRequest, error) {
	csr := &x509.CertificateRequest{
		Subject:     template.Subject,
		IPAddresses: template.IPAddresses,
		DNSNames:    template.DNSNames,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csr, priv)
	if err != nil {
		return nil, err
	}

	csr, err = x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, err
	}

	return csr, csr.CheckSignature()
}

type signRequest struct {
	caCertFile string
	caKeyFile  string
	private    interface{}
}

func readKey(filename string) (interface{}, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("could not open key file: %v", err)
	}

	block, _ := pem.Decode(content)

	if strings.Contains(block.Type, "RSA PRIVATE KEY") {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	} else if strings.Contains(block.Type, "EC PRIVATE KEY") {
		return x509.ParseECPrivateKey(block.Bytes)
	}

	return nil, errors.New("did not recognize private key")
}

func readCert(filename string) (*x509.Certificate, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(content)
	return x509.ParseCertificate(block.Bytes)
}

func doSign(template *x509.Certificate, r *signRequest) ([]byte, error) {
	caKey, err := readKey(r.caKeyFile)
	if err != nil {
		return nil, err
	}

	caCert, err := readCert(r.caCertFile)
	if err != nil {
		return nil, err
	}

	csr, err := mkCSR(template, r.private)
	if err != nil {
		return nil, err
	}

	template.Signature = csr.Signature
	template.SignatureAlgorithm = csr.SignatureAlgorithm
	template.PublicKeyAlgorithm = csr.PublicKeyAlgorithm
	template.PublicKey = csr.PublicKey

	return x509.CreateCertificate(rand.Reader, template, caCert, publicKey(r.private), caKey)
}

func main() {
	flag.Parse()

	if len(*host) == 0 && !*isCA {
		log.Fatalf("Missing required --host parameter (or tell us that it's a CA)")
	}

	var priv interface{}
	var err error

	if *rsaKey {
		priv, err = rsa.GenerateKey(rand.Reader, *rsaBits)
	} else {
		switch *ecdsaCurve {
		case "P224":
			priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		case "P256":
			priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case "P384":
			priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case "P521":
			priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		default:
			fmt.Fprintf(os.Stderr, "Unrecognized elliptic curve: %q", *ecdsaCurve)
			os.Exit(1)
		}
	}
	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
	}

	var notBefore time.Time
	if len(*validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006", *validFrom)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse creation date: %s\n", err)
			os.Exit(1)
		}
	}

	notAfter := notBefore.Add(*validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if *isClient {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	hosts := strings.Split(*host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if *isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	var derBytes []byte

	if *signCert != "" && *signKey != "" {
		derBytes, err = doSign(&template, &signRequest{
			private:    priv,
			caCertFile: *signCert,
			caKeyFile:  *signKey,
		})
		if err != nil {
			log.Fatalf("Failed to create & sign certificate: %s", err)
		}
	} else {
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
		if err != nil {
			log.Fatalf("Failed to create certificate: %s", err)
		}
	}

	certOut, err := os.Create(*outCert)
	if err != nil {
		log.Fatalf("failed to open cert.pem for writing: %s", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("failed to write data to %s: %s", *outCert, err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("error closing %s: %s", *outCert, err)
	}
	log.Printf("wrote %s\n", *outCert)

	keyOut, err := os.OpenFile(*outKey, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Printf("failed to open %s for writing: %s", *outKey, err)
		return
	}
	if err := pem.Encode(keyOut, pemBlockForKey(priv)); err != nil {
		log.Fatalf("failed to write data to %s: %s", *outKey, err)
	}
	if err := keyOut.Close(); err != nil {
		log.Fatalf("error closing %s: %s", *outKey, err)
	}
	log.Printf("wrote %s\n", *outKey)
}
