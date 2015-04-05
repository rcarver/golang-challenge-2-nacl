package main

import (
	"encoding/binary"
	"io"
	"testing"
)

func Test_SecureWriter_Read_fails(t *testing.T) {
	key := &[32]byte{}
	r, w := io.Pipe()
	sr := SecureReader{r, key}

	in := make([]byte, 100)
	binary.BigEndian.PutUint64(in, 30)
	copy(in[8:], []byte{'a', 'b', 'c', 'd'})
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
		t.Fatalf("want decryption error, got %s", err)
	}
}

func Test_SecureWriter_Write(t *testing.T) {
	key := &[32]byte{}
	buf := [4]byte{'a', 'b', 'c', 'd'}

	r, w := io.Pipe()
	sw := SecureWriter{w, key}

	var out = make([]byte, 1024)
	go io.ReadFull(r, out)

	c, err := sw.Write(buf[:])
	if err != nil {
		t.Fatalf("Want no error, got %s", err)
	}
	if c == 0 {
		t.Fatalf("Want bytes written, got %d", c)
	}

	headerSize := uint64(8)
	messageSize := binary.BigEndian.Uint64(out)

	if want := messageSize + headerSize; want != uint64(c) {
		t.Fatalf("want the right size result, want %d, got %d", want, c)
	}
	if want := out[messageSize+headerSize-1]; want == 0 {
		t.Fatalf("expect non-zero at the end of the data, got %#v", want)
	}
	if want := out[messageSize+headerSize]; want != 0 {
		t.Fatalf("expect zero past the data, got %#v", want)
	}
}

func Test_SecureWriter_Write_TooLong(t *testing.T) {
	key := &[32]byte{}
	buf := [maxMessageSize + 1]byte{}

	_, w := io.Pipe()
	sw := SecureWriter{w, key}

	c, err := sw.Write(buf[:])
	if err == nil {
		t.Fatalf("Want an error")
	}
	if c != 0 {
		t.Fatalf("Want 0 bytes written, got %d", c)
	}

}

func Test_Secure_ReadWrite(t *testing.T) {
	key := &[32]byte{}
	buf := [4]byte{'a', 'b', 'c', 'd'}

	r, w := io.Pipe()
	sr := SecureReader{r, key}
	sw := SecureWriter{w, key}

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
