package main

import (
	"bytes"
	"io"
	"testing"
)

func newFakeKeyPair(pub, priv string) *KeyPair {
	a, b := [32]byte{}, [32]byte{}
	copy(a[:], pub)
	copy(b[:], priv)
	return &KeyPair{&a, &b}
}

func Test_Server_handshake(t *testing.T) {
	kp := newFakeKeyPair("a", "b")
	s := Server{kp}

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

	commonKey, err := s.handshake(rw)
	if err != nil {
		t.Fatalf("Want no error in handshake")
	}

	// Server sent its public key to client.
	if !bytes.Equal(kp.pub[:], w.Bytes()) {
		t.Fatalf("Send key: got %#v, want %#v", w.Bytes(), kp.pub)
	}
	// Server received commonKey
	if commonKey == nil {
		t.Fatalf("Want shared key, got nil")
	}
}

func Test_Server_handle(t *testing.T) {
	kp := newFakeKeyPair("a", "b")
	s := Server{kp}
	r, w := io.Pipe()

	var out = make([]byte, 1024)
	var outSize = 0

	// Fake Client performs the expected IO. Uses server's keys for simplicity.
	go func() {
		var err error
		sr := NewSecureReader(r, kp.priv, kp.pub)
		sw := NewSecureWriter(w, kp.priv, kp.pub)
		if _, err := sw.Write([]byte("hello")); err != nil {
			t.Fatalf("Want no error writing message")
		}
		if outSize, err = sr.Read(out); err != nil {
			t.Fatalf("Want no error reading message")
		}
	}()

	// Fake a io.ReadWriter
	rw := struct {
		io.Reader
		io.Writer
	}{r, w}

	commonKey := kp.CommonKey()
	if err := s.handle(rw, commonKey); err != nil {
		t.Fatalf("Want no error in handle")
	}

	expectedOut := []byte("hello")
	if !bytes.Equal(out[:outSize], expectedOut) {
		t.Fatalf("Got %s, want %s", out[:5], expectedOut)
	}
}

func Test_Client_Handshake(t *testing.T) {
	kp := newFakeKeyPair("a", "b")
	c := Client{kp, nil}
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
		t.Fatalf("Got %s, want no error", err)
	}

	// Client sent its public key to server.
	if !bytes.Equal(kp.pub[:], w.Bytes()) {
		t.Fatalf("Send key: got %#v, want %#v", w.Bytes(), kp.pub)
	}
	// Client received server's shared key.
	if c.commonKey == nil {
		t.Fatalf("Got nil, want shared key")
	}
}

func Test_Client_SecureConn(t *testing.T) {
	kp := newFakeKeyPair("a", "b")
	commonKey := kp.CommonKey()
	c := Client{kp, commonKey}
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
		t.Fatalf("Got %s, want x", out)
	}
}
