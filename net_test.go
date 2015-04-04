package main

import (
	"bytes"
	"io"
	"testing"
)

func Test_Server_handshake(t *testing.T) {
	s := Server{
		pub: &[32]byte{'a'},
	}

	r := bytes.NewBuffer([]byte{})
	w := bytes.NewBuffer([]byte{})

	// Put the priv key on the read buffer, as if from the client.
	serverPriv := [32]byte{'p', 'r', 'i'}
	r.Write(serverPriv[:])

	// Fake a io.ReadWriter
	rw := struct {
		io.Reader
		io.Writer
	}{r, w}

	clientPriv, err := s.handshake(rw)
	if err != nil {
		t.Fatalf("want no error in handshake")
	}

	serverPub := make([]byte, 32)
	copy(serverPub[:], "a")
	if !bytes.Equal(serverPub, w.Bytes()) {
		t.Fatalf("pub want %#v, got %#v", serverPub, w.Bytes())
	}
	if !bytes.Equal(serverPriv[:], clientPriv[:]) {
		t.Fatalf("priv want %#v, got %#v", serverPriv, clientPriv)
	}
}

func Test_Server_handle(t *testing.T) {
	s := Server{
		pub: &[32]byte{'a'},
	}
	r, w := io.Pipe()

	var out = make([]byte, 1024)
	var outSize = 0

	clientPriv := &[32]byte{'b'}

	// Fake Client performs the expected IO.
	go func() {
		var err error
		sr := NewSecureReader(r, s.pub, clientPriv)
		sw := NewSecureWriter(w, s.pub, clientPriv)
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

	if err := s.handle(rw, clientPriv); err != nil {
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

	// Put the public key on the read buffer, as if from the server.
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

	if !bytes.Equal(serverPub[:], c.pub[:]) {
		t.Fatalf("pub want %#v, got %#v", serverPub, c.pub)
	}
	clientPriv := &[32]byte{'b'}
	if !bytes.Equal(clientPriv[:], w.Bytes()) {
		t.Fatalf("priv want %#v, got %#v", clientPriv, w.Bytes())
	}
}

func Test_Client_SecureConn(t *testing.T) {
	c := Client{
		pub:  &[32]byte{'a'},
		priv: &[32]byte{'b'},
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
