package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

// Server is the encrypted echo server.
type Server struct {
	keyPair *KeyPair
	logger  *log.Logger
}

// NewServer initializes a new Server with the key pair.
func NewServer(keyPair *KeyPair) *Server {
	logger := log.New(os.Stderr, "server: ", log.Lshortfile)
	return &Server{keyPair: keyPair, logger: logger}
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
			if err := s.handshake(conn); err != nil {
				s.info("Error performing handshake: %s", err)
			}
			if err := s.handle(conn); err != nil {
				s.info("Error handling client: %s", err)
			}
		}(conn)
	}
}

// handshake performs the key swap with the client.
func (s *Server) handshake(conn io.ReadWriter) error {

	// Send public key to the server
	s.info("Sending public key...\n")
	if _, err := conn.Write(s.keyPair.pub[:]); err != nil {
		return err
	}

	// Receive private key from the client.
	if _, err := conn.Read(s.keyPair.priv[:]); err != nil {
		return err
	}
	s.info("Received private key: %v\n", s.keyPair.priv)

	return nil
}

// handle is the main handler for client/server behavior.
func (s *Server) handle(conn io.ReadWriter) error {

	sr := NewSecureReader(conn, s.keyPair.pub, s.keyPair.priv)
	sw := NewSecureWriter(conn, s.keyPair.pub, s.keyPair.priv)

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
	keyPair *KeyPair
	logger  *log.Logger
}

// NewClient initializes a Client with the private key. Its public key
// will be retrieved from the server.
func NewClient(keyPair *KeyPair) *Client {
	logger := log.New(os.Stderr, "client: ", log.Lshortfile)
	return &Client{keyPair: keyPair, logger: logger}
}

// Handshake retrieves the public key from the server.
func (c *Client) Handshake(conn io.ReadWriter) error {

	// Receive public key from the server.
	if _, err := conn.Read(c.keyPair.pub[:]); err != nil {
		return fmt.Errorf("error reading: %s", err)
	}
	c.info("Received public key: %v\n", c.keyPair.pub)

	// Send private key to the server
	c.info("Sending private key...\n")
	if _, err := conn.Write(c.keyPair.priv[:]); err != nil {
		return fmt.Errorf("error writing: %s", err)
	}

	return nil
}

// SecureConn returns a ReadWriteCloser to communicate with the server.
// Requires that a peer's public key has been provided, probably by reading it
// via Handshake.
func (c *Client) SecureConn(conn io.ReadWriteCloser) io.ReadWriteCloser {
	r := NewSecureReader(conn, c.keyPair.pub, c.keyPair.priv)
	w := NewSecureWriter(conn, c.keyPair.pub, c.keyPair.priv)
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
