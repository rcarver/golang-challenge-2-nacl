package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

// Server is the secure echo server.
type Server struct {
	pub    *[32]byte
	logger *log.Logger
}

// NewServer initializes a new Server with the key pair.
func NewServer(pub *[32]byte) *Server {
	logger := log.New(os.Stderr, "server: ", log.Lshortfile)
	return &Server{pub: pub, logger: logger}
}

// Serve starts an infinite loop waiting for client connections.
func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			s.info("Failed to accept client: %s", err)
			return err
		}
		go func(conn net.Conn) {
			defer conn.Close()
			priv, err := s.handshake(conn)
			if err != nil {
				s.info("Error performing handshake: %s", err)
			}
			if err := s.handle(conn, priv); err != nil {
				s.info("Error handling client: %s", err)
			}
		}(conn)
	}
}

// handshake performs the key exchange with the client.
func (s *Server) handshake(conn io.ReadWriter) (*[32]byte, error) {

	// Send public key to the client.
	s.info("Sending public key...\n")
	if _, err := conn.Write(s.pub[:]); err != nil {
		return nil, err
	}

	// Receive private key from the client.
	priv := [32]byte{}
	if _, err := conn.Read(priv[:]); err != nil {
		return nil, err
	}
	s.info("Received private key: %v\n", priv)

	return &priv, nil
}

// handle takes care of client/server behavior after the handshake.
func (s *Server) handle(conn io.ReadWriter, priv *[32]byte) error {

	sr := NewSecureReader(conn, s.pub, priv)
	sw := NewSecureWriter(conn, s.pub, priv)

	// Read decrypted data from the client.
	s.info("Reading...\n")
	buf := make([]byte, 2048)
	c, err := sr.Read(buf)
	if err != nil {
		return err
	}
	s.info("Read %d bytes: %s\n", c, buf[:c])

	// Write encrypted data back to the client.
	s.info("Writing...\n")
	c, err = sw.Write(buf[:c])
	if err != nil {
		return err
	}
	s.info("Wrote %d bytes\n", c)

	return nil
}

func (s *Server) info(str string, v ...interface{}) {
	if s.logger != nil {
		s.logger.Printf(str, v...)
	}
}

// Client is the secure echo client.
type Client struct {
	pub    *[32]byte
	priv   *[32]byte
	logger *log.Logger
}

// NewClient initializes a Client with the private key. Its public key will be
// retrieved from the server.
func NewClient(priv *[32]byte) *Client {
	logger := log.New(os.Stderr, "client: ", log.Lshortfile)
	return &Client{priv: priv, logger: logger}
}

// Handshake performs the key exchange with the server.
func (c *Client) Handshake(conn io.ReadWriter) error {

	// Receive public key from the server.
	c.pub = &[32]byte{}
	if _, err := conn.Read(c.pub[:]); err != nil {
		return fmt.Errorf("error reading: %s", err)
	}
	c.info("Received public key: %v\n", c.pub)

	// Send private key to the server
	c.info("Sending private key...\n")
	if _, err := conn.Write(c.priv[:]); err != nil {
		return fmt.Errorf("error writing: %s", err)
	}

	return nil
}

// SecureConn returns a ReadWriteCloser to communicate with the server.
// Requires that the peer's public key has been provided, probably by reading it
// via Handshake.
func (c *Client) SecureConn(conn io.ReadWriteCloser) io.ReadWriteCloser {
	r := NewSecureReader(conn, c.pub, c.priv)
	w := NewSecureWriter(conn, c.pub, c.priv)
	return struct {
		io.Reader
		io.Writer
		io.Closer
	}{r, w, conn}
}

func (c *Client) info(str string, v ...interface{}) {
	if c.logger != nil {
		c.logger.Printf(str, v...)
	}
}
