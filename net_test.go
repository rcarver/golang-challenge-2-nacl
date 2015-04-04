package main

import (
	"bytes"
	"io"
	"testing"
)

func Test_Server_handshake(t *testing.T) {
	s := Server{
		pub:  &[32]byte{'a'},
		priv: &[32]byte{'b'},
	}

	r := bytes.NewBuffer([]byte{})
	w := bytes.NewBuffer([]byte{})

	// Put the client's public key on the read buffer.
	clientPub := [32]byte{'p', 'u', 'b'}
	r.Write(clientPub[:])

	// Fake a io.ReadWriter
	rw := struct {
		io.Reader
		io.Writer
	}{r, w}

	peersPub, err := s.handshake(rw)
	if err != nil {
		t.Fatalf("want no error in handshake")
	}

	// Server sent its public key to client.
	if !bytes.Equal(s.pub[:], w.Bytes()) {
		t.Fatalf("send key: want %#v, got %#v", s.pub, w.Bytes())
	}
	// Server received client's public key.
	if !bytes.Equal(clientPub[:], peersPub[:]) {
		t.Fatalf("recv key: want %#v, got %#v", clientPub, peersPub)
	}
}

func Test_Server_handle(t *testing.T) {
	s := Server{
		pub:  &[32]byte{'a'},
		priv: &[32]byte{'b'},
	}
	r, w := io.Pipe()

	var out = make([]byte, 1024)
	var outSize = 0

	// Fake Client performs the expected IO. Uses server's keys for simplicity.
	go func() {
		var err error
		sr := NewSecureReader(r, s.priv, s.pub)
		sw := NewSecureWriter(w, s.priv, s.pub)
		if _, err := sw.Write([]byte("hello")); err != nil {
			t.Fatalf("want no error writing message")
		}
		if outSize, err = sr.Read(out); err != nil {
			t.Fatalf("want no error reading message")
		}
	}()

	// Fake a io.ReadWriter
	rw := struct {
		io.Reader
		io.Writer
	}{r, w}

	if err := s.handle(rw, s.pub); err != nil {
		t.Fatalf("want no error in handle")
	}

	expectedOut := []byte("hello")
	if !bytes.Equal(out[:outSize], expectedOut) {
		t.Fatalf("want %s, got %s", expectedOut, out[:5])
	}
}

func Test_Client_Handshake(t *testing.T) {
	c := Client{
		pub:  &[32]byte{'a'},
		priv: &[32]byte{'b'},
	}
	r := bytes.NewBuffer([]byte{})
	w := bytes.NewBuffer([]byte{})

	// Put the server's public key on the read buffer.
	serverPub := [32]byte{'p', 'u', 'b'}
	r.Write(serverPub[:])

	// Fake a io.ReadWriter
	rw := struct {
		io.Reader
		io.Writer
	}{r, w}

	if err := c.Handshake(rw); err != nil {
		t.Fatalf("want no error, got %s", err)
	}

	// Client sent its public key to server.
	if !bytes.Equal(c.pub[:], w.Bytes()) {
		t.Fatalf("send key: want %#v, got %#v", c.pub, w.Bytes())
	}
	// Client received server's public key.
	if !bytes.Equal(serverPub[:], c.peersPub[:]) {
		t.Fatalf("recv key: want %#v, got %#v", serverPub, c.peersPub)
	}
}

func Test_Client_SecureConn(t *testing.T) {
	c := Client{
		priv:     &[32]byte{'b'},
		peersPub: &[32]byte{'a'},
	}
	r, w := io.Pipe()

	// Fake a io.ReadWriteCloser
	rwc := struct {
		io.Reader
		io.Writer
		io.Closer
	}{r, w, w}

	sc := c.SecureConn(rwc)

	var out = make([]byte, 1)
	go sc.Read(out)

	sc.Write([]byte{'x'})

	if string(out) != "x" {
		t.Fatalf("want x, got %s", out)
	}
}
