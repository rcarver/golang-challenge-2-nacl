package main

import (
	"bytes"
	"io"
	"testing"
)

func fakeKeyPair(pub, priv string) *KeyPair {
	a, b := [32]byte{}, [32]byte{}
	copy(a[:], priv)
	copy(b[:], pub)
	return &KeyPair{priv: &a, pub: &b}
}

func Test_Server_handshake(t *testing.T) {
	s := Server{
		keyPair: fakeKeyPair("a", "b"),
	}

	r := bytes.NewBuffer([]byte{})
	w := bytes.NewBuffer([]byte{})

	// Put the priv key on the read buffer, as if from the client.
	priv := [32]byte{'p', 'r', 'i'}
	r.Write(priv[:])

	// Fake a io.ReadWriter
	rw := struct {
		io.Reader
		io.Writer
	}{r, w}

	if err := s.handshake(rw); err != nil {
		t.Fatalf("want no error in handshake")
	}

	if !bytes.Equal(w.Bytes(), s.keyPair.pub[:]) {
		t.Fatalf("pub want %#v, got %#v", s.keyPair.pub[:], w.Bytes())
	}
	if !bytes.Equal(s.keyPair.priv[:], priv[:]) {
		t.Fatalf("priv want %#v, got %#v", priv, s.keyPair.priv)
	}
}

func Test_Server_handle(t *testing.T) {
	keyPair := fakeKeyPair("a", "b")
	s := Server{keyPair: keyPair}
	r, w := io.Pipe()

	var out = make([]byte, 1024)
	var outSize = 0

	// Fake Client performs the expected IO.
	go func() {
		var err error
		sr := NewSecureReader(r, keyPair.pub, keyPair.priv)
		sw := NewSecureWriter(w, keyPair.pub, keyPair.priv)
		if _, err := sw.Write([]byte("hello")); err != nil {
			t.Fatalf("want no error writing message")
		}
		if outSize, err = sr.Read(out); err != nil {
			t.Fatalf("want no error reading message")
		}
	}()

	if err := s.handle(&rwc{r, w, w}); err != nil {
		t.Fatalf("want no error in handle")
	}

	expectedOut := []byte("hello")
	if !bytes.Equal(out[:outSize], expectedOut) {
		t.Fatalf("want %s, got %s", expectedOut, out[:5])
	}
}

func Test_Client_Handshake(t *testing.T) {
	c := Client{
		keyPair: fakeKeyPair("a", "b"),
	}
	r := bytes.NewBuffer([]byte{})
	w := bytes.NewBuffer([]byte{})

	// Put the public key on the read buffer, as if from the server.
	pub := [32]byte{'p', 'u', 'b'}
	r.Write(pub[:])

	// Fake a io.ReadWriter
	rw := struct {
		io.Reader
		io.Writer
	}{r, w}

	if err := c.Handshake(rw); err != nil {
		t.Fatalf("want no error, got %s", err)
	}

	if !bytes.Equal(c.keyPair.pub[:], pub[:]) {
		t.Fatalf("pub want %#v, got %#v", pub, c.keyPair.pub)
	}
	if !bytes.Equal(w.Bytes(), c.keyPair.priv[:]) {
		t.Fatalf("priv want %#v, got %#v", c.keyPair.priv[:], w.Bytes())
	}
}

func Test_Client_SecureConn(t *testing.T) {
	c := Client{
		keyPair: fakeKeyPair("a", "b"),
	}
	r, w := io.Pipe()
	sc := c.SecureConn(&rwc{r, w, w})

	var out = make([]byte, 1)
	go sc.Read(out)

	sc.Write([]byte{'x'})

	if string(out) != "x" {
		t.Fatalf("want x, got %s", out)
	}
}
