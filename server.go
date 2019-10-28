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
	Addr         string       // TCP address to listen on, ":radius" if empty
	Handler      Handler      // handler to invoke
	SecretSource SecretSource // Secret source Store
	doneChan     chan struct{}
	mu           sync.Mutex
	waitGroup    *sync.WaitGroup
}

//var DefaultServe = func() {}

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

// ResponseWriter is used by RADIUS servers when replying to a RADIUS request.
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
	s := &Server{
		Addr:         addr,
		Handler:      handler,
		SecretSource: func(net.Addr) ([]byte, error) { return secret, nil },
	}
	return s
}

// ListenAndServe listens on the UDP network address addr and then calls
//
// ListenAndServe always returns a non-nil error.
func ListenAndServe(addr string, handler Handler, secretSource SecretSource) error {
	server := &Server{Addr: addr, Handler: handler, SecretSource: secretSource}
	return server.ListenAndServe()
}

// ListenAndServe listen on the UDP network address
func (s *Server) ListenAndServe() error {
	addr, err := net.ResolveUDPAddr("udp", s.Addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	s.waitGroup = &sync.WaitGroup{}
	for {
		select {
		case <-s.getDoneChan():
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

func (s *Server) getDoneChan() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getDoneChanLocked()
}

func (s *Server) getDoneChanLocked() chan struct{} {
	if s.doneChan == nil {
		s.doneChan = make(chan struct{})
	}
	return s.doneChan
}

func (s *Server) closeDoneChanLocked() {
	ch := s.getDoneChanLocked()
	select {
	case <-ch:
		// Already closed. Don't close again.
	default:
		// Safe to close here. We're the only closer, guarded
		// by s.mu.
		close(ch)
	}
}

var shutdownPollInterval = 500 * time.Millisecond

// Shutdown godoc
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.closeDoneChanLocked()
	s.mu.Unlock()

	waitChan := make(chan struct{}, 1)
	go func() {
		s.waitGroup.Wait()
		waitChan <- struct{}{}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-waitChan:
			return nil
		}
	}
}
