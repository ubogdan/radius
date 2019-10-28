# Radius Go library
Work in progress

### Example
```go
package main

import (
	"log"

	"github.com/ubogdan/radius"
)

type Server struct {
}

//func (s *Server) RadiusHandle(req *radius.Packet) *radius.Packet {
func (s *Server) ServeRADIUS(response radius.ResponseWriter, req *radius.Request) {
	switch req.Code {
	case radius.CodeAccessRequest:
		username := req.Get(radius.UserName).String()
		nasIPaddr, _ := req.Get(radius.NASIPAddress).IPAddr()
		nasPort, _ := req.Get(radius.NASPort).Integer()
		nasPortId, _ := req.Get(radius.NASPortId).Integer()
		calledStationId := req.Get(radius.CalledStationId).String()
		callingStationId := req.Get(radius.CallingStationId).String()

		log.Printf("Handle user:%s", username)
		log.Printf("Request: %s(%s) port:%d(%d) mac:%s", nasIPaddr, calledStationId,
			nasPort, nasPortId, callingStationId)

		eapAttribute, eapRequest := req.Lookup(radius.EAPMessage)
		if eapRequest {
			eapMessage,err := eapAttribute.EAPMessage()
			if err != nil {
				// Failed to decode EAP Message
				return
			}
			if eapMessage.Type == radius.EapTypeIdentity {
				res := req.Response(radius.CodeAccessAccept)
				message := radius.NewEAPMessage(radius.EapCodeSuccess, eapMessage.Identifier, 0, nil)
				res.Add(radius.EAPMessage, message)
				response.Write(res)
			}
		}

	case radius.CodeAccountingRequest:
		// accounting start or end
		response.Write(req.Response(radius.CodeAccountingResponse))
	}

	response.Write(req.Response(radius.CodeAccessReject))

}

func main() {
	log.Printf("New server")

	srv := radius.NewServer(":1812", []byte("secret1234"), &Server{})

	signalHandler := make(chan os.Signal, 1)
	signal.Notify(signalHandler, syscall.SIGINT, syscall.SIGTERM)
	errHandler := make(chan error)
	go func() {
		fmt.Println("waiting for packets...")
		err := srv.ListenAndServe()
		if err != nil {
			errHandler <- err
		}
	}()
	select {
	case <-signalHandler:
		log.Println("Shuting down ...")
		srv.Stop()
	case err := <-errHandler:
		log.Println("[ERR] %v", err.Error())
	}

}
```