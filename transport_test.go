package transport

import (
	. "testing"

	. "gopkg.in/check.v1"
)

type transportSuite struct{}

var _ = Suite(&transportSuite{})

func TestTransport(t *T) {
	TestingT(t)
}
