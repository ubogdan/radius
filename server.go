package radius

import (
	"fmt"
	"net"
	"sync"
	"time"
)

const AUTH_PORT = 1812
const ACCOUNTING_PORT = 1813

type Server struct {
	addr      string
	secret    string
	service   Service
	ch        chan struct{}
	waitGroup *sync.WaitGroup
	SecretSource
}

type Service interface {
	RadiusHandle(request *Packet) *Packet
}
type radiusEncoder interface {
	Encode() ([]byte, error)
}

// NewServer return a new Server given a addr, secret, and service
func NewServer(addr string, secret []byte, service Service) *Server {
	s := &Server{addr: addr,
		service:      service,
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
		go func(p []byte, addr net.Addr) {
			defer s.waitGroup.Done()

			secret, err := s.SecretSource(addr)
			if err != nil {
				return
			}
			pac, err := Parse(p, secret)
			if err != nil {
				fmt.Println("[pac.Decode]", err)
				return
			}
			pac.ClientAddr = addr.String()

			err = s.Send(conn, addr, s.service.RadiusHandle(pac))
			if err != nil {
				fmt.Println("[npac.Send]", err)
			}
		}(b[:n], addr)
	}
}
func (s *Server) Send(c net.PacketConn, addr net.Addr, p radiusEncoder) error {
	buf, err := p.Encode()
	if err != nil {
		return err
	}
	_, err = c.WriteTo(buf, addr)
	return err
}

// Stop will stop the server
func (s *Server) Stop() {
	close(s.ch)
	s.waitGroup.Wait()
}
