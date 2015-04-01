package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	return &SecureReader{r, priv, pub}
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	return &SecureWriter{w, priv, pub}
}

type RW struct {
	r io.Reader
	w io.Writer
	c net.Conn
}

func (rw *RW) Read(buf []byte) (int, error) {
	return rw.r.Read(buf)
}

func (rw *RW) Write(buf []byte) (int, error) {
	return rw.w.Write(buf)
}

func (rw *RW) Close() error {
	return rw.c.Close()
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	priv, pub := &[32]byte{}, &[32]byte{}
	_, err = conn.Read(priv[:])
	if err != nil {
		return nil, err
	}
	_, err = conn.Read(pub[:])
	if err != nil {
		return nil, err
	}

	fmt.Printf("PRIV: %s\n", priv)
	fmt.Printf("PUB: %s\n", pub)

	r := NewSecureReader(conn, priv, pub)
	w := NewSecureWriter(conn, priv, pub)

	return &RW{r, w, conn}, nil

}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		defer conn.Close()

		// Generate keys.
		priv, pub := &[32]byte{'p', 'r', 'i', 'v', '!'}, &[32]byte{'p', 'u', 'b', '!'}

		// Send private and public keys when a client connects.
		// The client should read 32 bytes for each key.
		conn.Write(priv[:])
		conn.Write(pub[:])

		fmt.Printf("server Reading...\n")
		buf := make([]byte, 2048)
		c, err := conn.Read(buf)
		if err != nil {
			return err
		}
		fmt.Printf("server Read: %d\n%s\n", c, hex.Dump(buf[:c]))

		fmt.Printf("server Writing...\n")
		c, err = conn.Write(buf[:c])
		if err != nil {
			return err
		}
		fmt.Printf("server Wrote %d\n", c)
	}
	return nil
}

func main() {
	port := flag.Int("l", 0, "Listen mode. Specify port")
	flag.Parse()

	// Server mode
	if *port != 0 {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()
		log.Fatal(Serve(l))
	}

	// Client mode
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <port> <message>", os.Args[0])
	}
	conn, err := Dial(fmt.Sprintf("localhost:%s", os.Args[1]))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("main Writing...\n")
	if _, err := conn.Write([]byte(os.Args[2])); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("main Reading...\n")
	buf := make([]byte, len(os.Args[2]))
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("main Read: %s\n", buf[:n])
	fmt.Printf("%s\n", buf[:n])
}
