package rdp

import (
	"bufio"
	"bytes"
	"io"
)

// newReader wraps a connection for the X.224 parser with a bounded buffer, so
// an unauthenticated peer cannot make us allocate freely.
func newReader(r io.Reader) *bufio.Reader {
	return bufio.NewReaderSize(r, MaxPDU)
}

func newReaderFromBytes(b []byte) *bufio.Reader {
	return bufio.NewReaderSize(bytes.NewReader(b), MaxPDU)
}
