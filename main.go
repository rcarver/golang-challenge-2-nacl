package main

import (
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
	logger := log.New(os.Stderr, "client: ", log.Lshortfile)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	// Generate private key.
	priv := &[32]byte{'p', 'r', 'i', 'v', '!'}

	// Receive private key from the server.
	logger.Printf("Receiving public key...\n")
	pub := &[32]byte{}
	if _, err = conn.Read(pub[:]); err != nil {
		return nil, err
	}
	logger.Printf("Received public key: %v\n", pub)

	// Set up secure read and write.
	r := NewSecureReader(conn, priv, pub)
	w := NewSecureWriter(conn, priv, pub)
	return &RW{r, w, conn}, nil

}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	logger := log.New(os.Stderr, "server: ", log.Lshortfile)
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		defer conn.Close()

		// Generate public key.
		pub := &[32]byte{'p', 'u', 'b', '!'}

		// Send public key to the client.
		logger.Printf("Sending public key...\n")
		if _, err := conn.Write(pub[:]); err != nil {
			return err
		}

		// Read input from the client.
		logger.Printf("Reading...\n")
		buf := make([]byte, 2048)
		c, err := conn.Read(buf)
		if err != nil {
			return err
		}
		logger.Printf("Read %d bytes\n", c)

		// Echo it back unmodified.
		logger.Printf("Writing...\n")
		c, err = conn.Write(buf[:c])
		if err != nil {
			return err
		}
		logger.Printf("Wrote %d bytes\n", c)
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
	if _, err := conn.Write([]byte(os.Args[2])); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, len(os.Args[2]))
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", buf[:n])
}
