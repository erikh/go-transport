PKG := github.com/erikh/go-transport
DOCKER_DIR := /go/src

test: build
	docker run --rm -it -w "$(DOCKER_DIR)/$(PKG)" -v "${GOPATH}/src/$(PKG):$(DOCKER_DIR)/$(PKG)" go-transport bash -c 'make do-test'

build:
	@if [ ! -f $(shell which box) ]; \
	then \
		echo "Need to install box to build the docker images we use. Requires root access."; \
		curl -sSL box-builder.sh | sudo bash; \
	fi
	box --no-tty -t go-transport box.rb

# XXX this task is intended to run inside the above container
do-test:
	go get github.com/FiloSottile/mkcert
	mkcert --install
	cd certgen && bash test-certgen.sh
	go install -v -tags nobuild github.com/erikh/go-transport/certgen/...
	go get -t github.com/erikh/go-transport/...
	go test -race -v github.com/erikh/go-transport -check.v
