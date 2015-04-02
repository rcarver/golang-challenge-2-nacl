package main

import (
	"io"
	"testing"
)

func Test_SecureWriter_Read_fails(t *testing.T) {
	priv, pub := &[32]byte{}, &[32]byte{}

	r, w := io.Pipe()
	sr := SecureReader{r, priv, pub}

	in := make([]byte, 1024)
	copy(in, []byte{'a', 'b', 'c', 'd'})
	go w.Write(in)

	var out = make([]byte, 1024)
	c, err := sr.Read(out)

	if c != 0 {
		t.Fatalf("want 0 bytes")
	}
	if err == nil {
		t.Fatalf("want error")
	}
	if err.Error() != "decryption failed" {
		t.Fatalf("want decryption error")
	}
}

func Test_SecureWriter_Write(t *testing.T) {
	priv, pub := &[32]byte{}, &[32]byte{}
	buf := [4]byte{'a', 'b', 'c', 'd'}

	r, w := io.Pipe()
	sw := SecureWriter{w, priv, pub}

	var out = make([]byte, 1024)
	go io.ReadFull(r, out)

	c, err := sw.Write(buf[:])
	if err != nil {
		t.Fatalf("Want no error, got %s", err)
	}
	if c == 0 {
		t.Fatalf("Want bytes written, got %d", c)
	}

	if string(out[:4]) == "abcd" {
		t.Fatalf("want encrypted, got %s", out)
	}
}

func Test_SecureWriter_Write_TooLong(t *testing.T) {
	priv, pub := &[32]byte{}, &[32]byte{}
	buf := [3073]byte{}

	_, w := io.Pipe()
	sw := SecureWriter{w, priv, pub}

	c, err := sw.Write(buf[:])
	if err == nil {
		t.Fatalf("Want an error")
	}
	if c != 0 {
		t.Fatalf("Want 0 bytes written, got %d", c)
	}

}

func Test_Secure_ReadWrite(t *testing.T) {
	priv, pub := &[32]byte{}, &[32]byte{}
	buf := [4]byte{'a', 'b', 'c', 'd'}

	r, w := io.Pipe()
	sr := SecureReader{r, priv, pub}
	sw := SecureWriter{w, priv, pub}

	var out = make([]byte, 1024)
	var readBytes = -1
	go func() {
		var err error
		readBytes, err = sr.Read(out)
		if err != nil {
			t.Fatalf("Want no error, got %s", err)
		}
	}()

	_, err := sw.Write(buf[:])
	if err != nil {
		t.Fatalf("Want no error, got %s", err)
	}

	if readBytes != 4 {
		t.Fatalf("want 4 bytes, got %d", readBytes)
	}
	if string(out[:4]) != "abcd" {
		t.Fatalf("want abcd, got %s", out)
	}
}
