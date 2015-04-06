package main

import (
	"bytes"
	"io"
	"testing"
)

func newFakeKeyPair(pub, priv, peersPub string) *KeyPair {
	a, b, c := [32]byte{}, [32]byte{}, [32]byte{}
	copy(a[:], pub)
	copy(b[:], priv)
	copy(c[:], peersPub)
	return &KeyPair{&a, &b, &c}
}

func Test_Server_handshake(t *testing.T) {
	ks := newFakeKeyPair("a", "b", "")
	s := Server{ks}

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

	err := s.handshake(rw, ks)
	if err != nil {
		t.Fatalf("want no error in handshake")
	}

	// Server sent its public key to client.
	if !bytes.Equal(ks.pub[:], w.Bytes()) {
		t.Fatalf("send key: want %#v, got %#v", ks.pub, w.Bytes())
	}
	// Server received client's public key.
	if !bytes.Equal(clientPub[:], ks.peersPub[:]) {
		t.Fatalf("recv key: want %#v, got %#v", clientPub, ks.peersPub)
	}
}

func Test_Server_handle(t *testing.T) {
	ks := newFakeKeyPair("", "b", "a")
	s := Server{ks}
	r, w := io.Pipe()

	var out = make([]byte, 1024)
	var outSize = 0

	// Fake Client performs the expected IO. Uses server's keys for simplicity.
	go func() {
		var err error
		sr := NewSecureReader(r, ks.priv, ks.peersPub)
		sw := NewSecureWriter(w, ks.priv, ks.peersPub)
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

	if err := s.handle(rw, ks); err != nil {
		t.Fatalf("want no error in handle")
	}

	expectedOut := []byte("hello")
	if !bytes.Equal(out[:outSize], expectedOut) {
		t.Fatalf("want %s, got %s", expectedOut, out[:5])
	}
}

func Test_Client_Handshake(t *testing.T) {
	ks := newFakeKeyPair("a", "b", "")
	c := Client{ks}
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
	if !bytes.Equal(ks.pub[:], w.Bytes()) {
		t.Fatalf("send key: want %#v, got %#v", ks.pub, w.Bytes())
	}
	// Client received server's public key.
	if !bytes.Equal(serverPub[:], ks.peersPub[:]) {
		t.Fatalf("recv key: want %#v, got %#v", serverPub, ks.peersPub)
	}
}

func Test_Client_SecureConn(t *testing.T) {
	ks := newFakeKeyPair("", "b", "a")
	c := Client{ks}
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
