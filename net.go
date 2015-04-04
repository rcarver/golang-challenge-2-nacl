package main

import (
	"fmt"
	"io"
	"net"
)

// Server is the secure echo server.
type Server struct {
	pub  *[32]byte
	priv *[32]byte
}

// NewServer initializes a new Server with the key pair. The server will
// perform a handshake with each client to exchange public keys.
func NewServer(pub, priv *[32]byte) *Server {
	return &Server{pub: pub, priv: priv}
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
			peersPub, err := s.handshake(conn)
			if err != nil {
				s.debug("Error performing handshake: %s", err)
			}
			if err := s.handle(conn, peersPub); err != nil {
				s.debug("Error handling client: %s", err)
			}
		}(conn)
	}
}

// handshake performs the key exchange with the client.
func (s *Server) handshake(conn io.ReadWriter) (*[32]byte, error) {

	// Send public key to the client.
	s.debug("Sending public key %v\n", s.pub)
	if _, err := conn.Write(s.pub[:]); err != nil {
		return nil, err
	}

	// Receive public key from the client.
	peersPub := [32]byte{}
	if _, err := conn.Read(peersPub[:]); err != nil {
		return nil, err
	}
	s.debug("Received peer's public key: %v\n", peersPub)

	return &peersPub, nil
}

// handle takes care of client/server behavior after the handshake.
func (s *Server) handle(conn io.ReadWriter, peersPub *[32]byte) error {

	sr := NewSecureReader(conn, s.priv, peersPub)
	sw := NewSecureWriter(conn, s.priv, peersPub)

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
	pub      *[32]byte
	priv     *[32]byte
	peersPub *[32]byte
}

// NewClient initializes a Client with its own key pair. The client will
// perform a handshake with the server to exchange public keys.
func NewClient(pub, priv *[32]byte) *Client {
	return &Client{pub: pub, priv: priv}
}

// Handshake performs the public key exchange with the server.
func (c *Client) Handshake(conn io.ReadWriter) error {

	// Receive public key from the server.
	c.peersPub = &[32]byte{}
	if _, err := conn.Read(c.peersPub[:]); err != nil {
		return fmt.Errorf("error reading: %s", err)
	}
	c.debug("Received peer's public key: %v\n", c.peersPub)

	// Send public key to the server
	c.debug("Sending public key %v\n", c.pub)
	if _, err := conn.Write(c.pub[:]); err != nil {
		return fmt.Errorf("error writing: %s", err)
	}

	return nil
}

// SecureConn returns a ReadWriteCloser to communicate with the server.
// Requires that the peer's public key has been provided, probably by getting
// it via Handshake.
func (c *Client) SecureConn(conn io.ReadWriteCloser) io.ReadWriteCloser {
	r := NewSecureReader(conn, c.priv, c.peersPub)
	w := NewSecureWriter(conn, c.priv, c.peersPub)
	return struct {
		io.Reader
		io.Writer
		io.Closer
	}{r, w, conn}
}

func (c *Client) debug(str string, v ...interface{}) {
	debugf("client: %s", fmt.Sprintf(str, v))
}
