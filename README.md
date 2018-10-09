## go-transport: easy-to-use TLS-backed transports for cert auth scenarios

[![Build Status](https://travis-ci.org/erikh/go-transport.svg?branch=master)](https://travis-ci.org/erikh/go-transport) [![GoDoc](https://godoc.org/github.com/erikh/go-transport?status.svg)](https://godoc.org/github.com/erikh/go-transport)

go-transport implements basic TLS-backed transports. These transports can
create both clients and servers that can auth via client cert; and if the cert
is omitted, they will magically transform into plain connections. Be careful
with nil pointers!  The goal is to provide safe, common functionality from the
crypto/tls, net/http and net packages based on modern practices for secure
connectivity at the cost of the flexibility these packages provide.

transport includes HTTP and TCP functionality, as well as a certificate
utility framework that sits on top of most of the crypto, pki and x509
packages.

Additionally, it resolves CRLs in a meaningful way at the time of connect, if a
CRL is provided.

Please note that there are many constraints in the system as of now:

* largely only situations where client certs are needed is where this library
  excels; I hope to change that in the future but this is my current
  use-case...  So until that changes, this library will likely not grow much.
* only ecdsa keys are supported
* You must use a CA that can be verified; this means that self-signed certs
  are largely out. Build a real CA instead.

## Example

```go
// you need to generate a CA and certs first. to generate certs you can use our
// example certgen program:
//
// go install -tags nobuild github.com/erikh/go-transport/certgen/...
//
// Then execute the following commands in the same dir as this source code:
//
// certgen -ca -out-cert ca.crt -out-key ca.key
// certgen -sign-cert ca.crt -sign-key ca.key --host localhost -out-cert server.crt -out-key server.key
// certgen -sign-cert ca.crt -sign-key ca.key -client --host localhost -out-cert client.crt -out-key client.key
//
package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	transport "github.com/erikh/go-transport"
)

type successHandler struct{}

func (h *successHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "hello from go-transport")
}

func main() {
	cert, err := transport.LoadCert("ca.crt", "server.crt", "server.key", "")
	if err != nil {
		panic(err)
	}

	clientCert, err := transport.LoadCert("ca.crt", "client.crt", "client.key", "")
	if err != nil {
		panic(err)
	}

	server, err := transport.NewHTTP(cert)
	if err != nil {
		panic(err)
	}

	client, err := transport.NewHTTP(clientCert)
	if err != nil {
		panic(err)
	}

	s, l, err := server.Server("localhost:8000", &successHandler{})
	if err != nil {
		panic(err)
	}

	go s.Serve(l)
	defer l.Close()

	resp, err := client.Client(nil).Get("https://localhost:8000")
	if err != nil {
		panic(err)
	}
	if resp.StatusCode != 200 {
		panic(resp.Status)
	}

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(content))
}
```

## Future Plans

* Websockets
* Server side only TLS

## License

Copyright (c) 2018 Erik Hollensbe

MIT License

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Author

Erik Hollensbe <h-e@hollensbe.org>
