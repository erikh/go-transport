## go-transport: easy-to-use TLS-backed transports for many situations

**not quite ready for use; check back in a few days.**

go-transport implements basic TLS-backed transports. These transports
can create both clients and servers; and if the cert is omitted, they will
magically transform into plain connections. Be careful with nil pointers!
The goal is to provide safe, common functionality from the crypto/tls,
net/http and net packages based on modern practices for secure connectivity
at the cost of the flexibility these packages provide.

transport includes HTTP and TCP functionality, as well as a certificate
utility framework that sits on top of most of the crypto, pki and x509
packages.

Please note that there are many constraints in the system as of now:

* only ecdsa keys are supported
* CRLs are supported; but you must manually check them (we also have
  whitelisting of serial numbers if you'd prefer to avoid CRLs entirely)
* You must use a CA that can be verified; this means that self-signed certs
  are largely out. Build a real CA instead.

## Example

coming after I write some tests.

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
