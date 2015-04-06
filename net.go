package main

import (
	"fmt"
	"io"
	"net"
)

// Server is the secure echo server.
type Server struct {
	keyPair *KeyPair
}

// NewServer initializes a new Server with its own keys. The server will
// perform a handshake with each client to exchange public keys.
func NewServer(kp *KeyPair) *Server {
	return &Server{kp}
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
			// Each client gets its own set of key set to handshake
			// with because we need to manage the pub/priv keypair
			// independently for each client.
			kp := s.keyPair.Copy()
			err := s.handshake(conn, kp)
			if err != nil {
				s.debug("Error performing handshake: %s", err)
			}
			if err := s.handle(conn, kp); err != nil {
				s.debug("Error handling client: %s", err)
			}
		}(conn)
	}
}

// handshake performs the key exchange with the client.
func (s *Server) handshake(conn io.ReadWriter, kp *KeyPair) error {
	s.debug("Performing key exchange...\n")
	if err := kp.Exchange(conn); err != nil {
		return err
	}
	return nil
}

// handle takes care of client/server behavior after the handshake.
func (s *Server) handle(conn io.ReadWriter, kp *KeyPair) error {
	// Setup encrypted reader/writer to communicate with the client.
	sharedKey := kp.PeersSharedKey()
	sr := &SecureReader{conn, sharedKey}
	sw := &SecureWriter{conn, sharedKey}

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
	keyPair *KeyPair
}

// NewClient initializes a Client with its own keys. The client will perform a
// handshake with the server to exchange public keys.
func NewClient(kp *KeyPair) *Client {
	return &Client{kp}
}

// Handshake performs the public key exchange with the server.
func (c *Client) Handshake(conn io.ReadWriter) error {
	c.debug("Performing key exchange...\n")
	if err := c.keyPair.Exchange(conn); err != nil {
		return err
	}
	return nil
}

// SecureConn returns a ReadWriteCloser to communicate with the server.
// Requires that the peer's public key has been provided, probably by getting
// it via Handshake.
func (c *Client) SecureConn(conn io.ReadWriteCloser) io.ReadWriteCloser {
	sharedKey := c.keyPair.PeersSharedKey()
	r := &SecureReader{conn, sharedKey}
	w := &SecureWriter{conn, sharedKey}
	return struct {
		io.Reader
		io.Writer
		io.Closer
	}{r, w, conn}
}

func (c *Client) debug(str string, v ...interface{}) {
	debugf("client: %s", fmt.Sprintf(str, v))
}
