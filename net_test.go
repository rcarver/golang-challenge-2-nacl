package main

import (
	"bytes"
	"io"
	"testing"
)

func Test_Server_handleClient(t *testing.T) {
	s := Server{
		pub: &[32]byte{'b'},
	}
	r, w := io.Pipe()

	var key = make([]byte, 1024)
	var keySize = 0
	var out = make([]byte, 1024)
	var outSize = 0

	// Fake Client performs the expected IO.
	go func() {
		var err error
		if keySize, err = r.Read(key); err != nil {
			t.Fatalf("want no error reading key")
		}
		if _, err := w.Write([]byte{'h', 'e', 'l', 'l', 'o'}); err != nil {
			t.Fatalf("want no error writing message")
		}
		if outSize, err = r.Read(out); err != nil {
			t.Fatalf("want no error reading message")
		}
	}()

	if err := s.handleClient(&rwc{r, w, w}); err != nil {
		t.Fatalf("want no error in handleClient")
	}

	expectedKey := make([]byte, 32)
	copy(expectedKey, "b")
	if !bytes.Equal(key[:keySize], expectedKey) {
		t.Fatalf("want %s, got %s", expectedKey, key[:1])
	}

	expectedOut := make([]byte, outSize)
	copy(expectedOut, "hello")
	if !bytes.Equal(out[:outSize], expectedOut) {
		t.Fatalf("want %s, got %s", expectedOut, out[:5])
	}

}

func Test_Client_RetrievePublicKey(t *testing.T) {
	c := Client{}

	r := bytes.NewBufferString("abcd")
	if err := c.RetrievePublicKey(r); err != nil {
		t.Fatalf("want no error")
	}

	expected := [32]byte{'a', 'b', 'c', 'd'}
	if *c.pub != expected {
		t.Fatalf("want %#v, got %#v", expected, c.pub)
	}
}

func Test_Client_SecureConn(t *testing.T) {
	c := Client{
		priv: &[32]byte{'a'},
		pub:  &[32]byte{'b'},
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
