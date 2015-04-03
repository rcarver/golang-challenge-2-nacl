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
	r, w := io.Pipe()

	var pubKey, privKey = make([]byte, 1024), make([]byte, 1024)
	var pubKeySize, privKeySize = 0, 0

	// Fake Client performs the expected IO.
	go func() {
		var err error
		if pubKeySize, err = r.Read(pubKey); err != nil {
			t.Fatalf("want no error reading pubKey")
		}
		if privKeySize, err = r.Read(privKey); err != nil {
			t.Fatalf("want no error reading privKey")
		}
	}()

	if err := s.handshake(&rwc{r, w, w}); err != nil {
		t.Fatalf("want no error in handshake")
	}

	expectedPubKey := make([]byte, 32)
	copy(expectedPubKey, "a")
	if !bytes.Equal(pubKey[:pubKeySize], expectedPubKey) {
		t.Fatalf("want %s, got %s", expectedPubKey, pubKey[:1])
	}
	expectedPrivKey := make([]byte, 32)
	copy(expectedPrivKey, "b")
	if !bytes.Equal(privKey[:privKeySize], expectedPrivKey) {
		t.Fatalf("want %s, got %s", expectedPrivKey, privKey[:1])
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
	c := Client{keyPair: &KeyPair{}}

	pub := [32]byte{'p', 'u', 'b'}
	priv := [32]byte{'p', 'r', 'i'}
	buf := []byte{}
	copy(buf, pub[:])
	copy(buf, priv[:])

	r := bytes.NewBuffer(buf)
	if err := c.Handshake(r); err != nil {
		t.Fatalf("want no error")
	}

	if *c.keyPair.pub != pub {
		t.Fatalf("want %#v, got %#v", pub, c.keyPair.pub)
	}
	if *c.keyPair.priv != priv {
		t.Fatalf("want %#v, got %#v", priv, c.keyPair.priv)
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
