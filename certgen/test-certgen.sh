#!/bin/sh

set -e

go run generate_cert.go -ca -out-cert ca.crt -out-key ca.key
go run generate_cert.go -sign-cert ca.crt -sign-key ca.key --host localhost -out-cert cert.crt -out-key cert.key
openssl verify -CAfile ca.crt cert.crt
