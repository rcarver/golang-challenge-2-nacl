package main

import (
	"fmt"
	"io"
	"net"
)

// Server is the secure echo server.
type Server struct {
	keySet *KeySet
}

// NewServer initializes a new Server with its own keys. The server will
// perform a handshake with each client to exchange public keys.
func NewServer(ks *KeySet) *Server {
	return &Server{ks}
}

// Serve starts an infinite loop waiting for client connections.
func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			s.debug("Failed to accept client: %s", err)
			return err
		}
		go func(conn net.Conn) {
			defer conn.Close()
			ks := s.keySet.Copy()
			err := s.handshake(conn, ks)
			if err != nil {
				s.debug("Error performing handshake: %s", err)
			}
			if err := s.handle(conn, ks); err != nil {
				s.debug("Error handling client: %s", err)
			}
		}(conn)
	}
}

// handshake performs the key exchange with the client.
func (s *Server) handshake(conn io.ReadWriter, ks *KeySet) error {
	s.debug("Performing key exchange...\n")
	if err := ks.Exchange(conn); err != nil {
		return err
	}
	return nil
}

// handle takes care of client/server behavior after the handshake.
func (s *Server) handle(conn io.ReadWriter, keySet *KeySet) error {

	pub, priv := keySet.PeersKeyPair()
	sr := NewSecureReader(conn, priv, pub)
	sw := NewSecureWriter(conn, priv, pub)

	// Read decrypted data from the client.
	s.debug("Reading...\n")
	buf := make([]byte, 2048)
	c, err := sr.Read(buf)
	if err != nil {
		return err
	}
	s.debug("Read %d bytes: %s\n", c, buf[:c])

	// Write encrypted data back to the client.
	s.debug("Writing...\n")
	c, err = sw.Write(buf[:c])
	if err != nil {
		return err
	}
	s.debug("Wrote %d bytes\n", c)

	return nil
}

func (s *Server) debug(str string, v ...interface{}) {
	debugf("server: %s", fmt.Sprintf(str, v))
}

// Client is the secure echo client.
type Client struct {
	keySet *KeySet
}

// NewClient initializes a Client with its own keys. The client will perform a
// handshake with the server to exchange public keys.
func NewClient(ks *KeySet) *Client {
	return &Client{ks}
}

// Handshake performs the public key exchange with the server.
func (c *Client) Handshake(conn io.ReadWriter) error {
	c.debug("Performing key exchange...\n")
	if err := c.keySet.Exchange(conn); err != nil {
		return err
	}
	return nil
}

// SecureConn returns a ReadWriteCloser to communicate with the server.
// Requires that the peer's public key has been provided, probably by getting
// it via Handshake.
func (c *Client) SecureConn(conn io.ReadWriteCloser) io.ReadWriteCloser {
	pub, priv := c.keySet.PeersKeyPair()
	r := NewSecureReader(conn, priv, pub)
	w := NewSecureWriter(conn, priv, pub)
	return struct {
		io.Reader
		io.Writer
		io.Closer
	}{r, w, conn}
}

func (c *Client) debug(str string, v ...interface{}) {
	debugf("client: %s", fmt.Sprintf(str, v))
}
