package radius

import (
	"net"
	"strconv"
)

// Type is the RADIUS attribute type.
type Type int

// EapType is the EAP attribute type.
type EapType uint8

// ResponseWriter godoc
type ResponseWriter interface {
	Write(packet *Packet) error
}

// SecretStore supplies RADIUS servers with the secret that should be used for
// authorizing and decrypting packets.
//
// ctx is canceled if the server's Shutdown method is called.
//
// Returning an empty secret will discard the incoming packet.
type SecretSource func(remoteAddr net.Addr) ([]byte, error)

// TypeInvalid is a Type that can be used to represent an invalid RADIUS
// attribute type.
const TypeInvalid Type = -1

const (
	EapTypeIdentity         EapType = 1
	EapTypeNotification     EapType = 2
	EapTypeNak              EapType = 3 //Response only
	EapTypeMd5Challenge     EapType = 4
	EapTypeOneTimePassword  EapType = 5 //otp
	EapTypeGenericTokenCard EapType = 6 //gtc
	EapTypeMSCHAPV2         EapType = 26
	EapTypeExpandedTypes    EapType = 254
	EapTypeExperimentalUse  EapType = 255
)

func (c EapType) String() string {
	switch c {
	case EapTypeIdentity:
		return "Identity"
	case EapTypeNotification:
		return "Notification"
	case EapTypeNak:
		return "Nak"
	case EapTypeMd5Challenge:
		return "Md5Challenge"
	case EapTypeOneTimePassword:
		return "OneTimePassword"
	case EapTypeGenericTokenCard:
		return "GenericTokenCard"
	case EapTypeMSCHAPV2:
		return "MSCHAPV2"
	case EapTypeExpandedTypes:
		return "ExpandedTypes"
	case EapTypeExperimentalUse:
		return "ExperimentalUse"
	default:
		return "unknow EapType " + strconv.Itoa(int(c))
	}
}
