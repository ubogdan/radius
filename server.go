package radius

import (
	"context"
	"net"
	"sync"
	"time"
)

const AUTH_PORT = 1812
const ACCOUNTING_PORT = 1813

type Server struct {
	addr      string
	ch        chan struct{}
	waitGroup *sync.WaitGroup
	Handler
	SecretSource
}

// Request is an incoming RADIUS request that is being handled by the server.
type Request struct {
	// LocalAddr is the local address on which the incoming RADIUS request
	// was received.
	LocalAddr net.Addr
	// RemoteAddr is the address from which the incoming RADIUS request
	// was sent.
	RemoteAddr net.Addr

	// Packet is the RADIUS packet sent in the request.
	*Packet

	ctx context.Context
}

// ResponseWriter godoc
type ResponseWriter interface {
	Write(packet *Packet) error
}

type Handler interface {
	ServeRADIUS(ResponseWriter, *Request)
}

type responseWriter struct {
	// listener that received the packet
	conn net.PacketConn
	addr net.Addr
}

func (r *responseWriter) Write(packet *Packet) error {
	encoded, err := packet.Encode()
	if err != nil {
		return err
	}
	if _, err := r.conn.WriteTo(encoded, r.addr); err != nil {
		return err
	}
	return nil
}

// NewServer return a new Server given a addr, secret, and service
func NewServer(addr string, secret []byte, handler Handler) *Server {
	s := &Server{addr: addr,
		Handler:      handler,
		ch:           make(chan struct{}),
		waitGroup:    &sync.WaitGroup{},
		SecretSource: func(net.Addr) ([]byte, error) { return secret, nil },
	}
	return s
}

// ListenAndServe listen on the UDP network address
func (s *Server) ListenAndServe() error {
	addr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	for {
		select {
		case <-s.ch:
			return nil
		default:
		}
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		b := make([]byte, 4096)
		n, addr, err := conn.ReadFrom(b)
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				continue
			}
			return err
		}

		s.waitGroup.Add(1)
		go func(p []byte, remoteAddr net.Addr) {
			defer s.waitGroup.Done()

			secret, err := s.SecretSource(remoteAddr)
			if err != nil {
				return
			}

			if len(secret) == 0 {
				return
			}

			packet, err := Parse(p, secret)
			if err != nil {
				return
			}

			response := responseWriter{
				conn: conn,
				addr: remoteAddr,
			}

			request := Request{
				LocalAddr:  conn.LocalAddr(),
				RemoteAddr: remoteAddr,
				Packet:     packet,
				//ctx:        s.ctx,
			}

			s.Handler.ServeRADIUS(&response, &request)
		}(b[:n], addr)
	}
}

// Stop will stop the server
func (s *Server) Stop() {
	close(s.ch)
	s.waitGroup.Wait()
}
