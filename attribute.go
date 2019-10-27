package radius

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"time"
)

// ErrNoAttribute is returned when an attribute was not found when one was
// expected.
var ErrNoAttribute = errors.New("radius: attribute not found")

// Attribute is a wire encoded RADIUS attribute.
type Attribute []byte

type EapMessage struct {
	Code       EapCode
	Identifier uint8
	Type       EapType
	Data       Attribute
}

// String returns the given attribute as a string.
func (a Attribute) String() string {
	return string(a)
}

// NewString returns a new Attribute from the given string. An error is returned
// if the string length is greater than 253.
func NewString(s string) (Attribute, error) {
	if len(s) > 253 {
		return nil, errors.New("string too long")
	}
	return Attribute(s), nil
}

// Bytes returns the given Attribute as a byte slice.
func (a Attribute) Bytes() []byte {
	b := make([]byte, len(a))
	copy(b, []byte(a))
	return b
}

// NewBytes returns a new Attribute from the given byte slice. An error is
// returned if the slice is longer than 253.
func NewBytes(b []byte) (Attribute, error) {
	if len(b) > 253 {
		return nil, errors.New("value too long")
	}
	a := make(Attribute, len(b))
	copy(a, Attribute(b))
	return a, nil
}

// Integer returns the given attribute as an integer. An error is returned if
// the attribute is not 4 bytes long.
func (a Attribute) Integer() (uint32, error) {
	if len(a) != 4 {
		return 0, errors.New("invalid length")
	}
	return binary.BigEndian.Uint32(a), nil
}

// NewInt creates a new Attribute from the given integer value.
func NewInt(i uint32) Attribute {
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, i)
	return Attribute(v)
}

// Int64 returns the given attribute as an integer. An error is returned if
// the attribute is not 8 bytes long.
func (a Attribute) Int64() (uint64, error) {
	if len(a) != 8 {
		return 0, errors.New("invalid length")
	}
	return binary.BigEndian.Uint64(a), nil
}

// NewInt64 creates a new Attribute from the given integer value.
func NewInt64(i uint64) Attribute {
	v := make([]byte, 8)
	binary.BigEndian.PutUint64(v, i)
	return Attribute(v)
}

// Time returns the given Attribute as time.Time. An error is returned if the
// attribute is not 4 bytes long.
func (a Attribute) Time() (time.Time, error) {
	if len(a) != 4 {
		return time.Time{}, errors.New("invalid length")
	}
	sec := binary.BigEndian.Uint32([]byte(a))
	return time.Unix(int64(sec), 0), nil
}

// NewTime returns a new Attribute from the given time.Time.
func NewTime(t time.Time) (Attribute, error) {
	unix := t.Unix()
	if unix > math.MaxUint32 {
		return nil, errors.New("time out of range")
	}
	a := make([]byte, 4)
	binary.BigEndian.PutUint32(a, uint32(t.Unix()))
	return a, nil
}

// IPAddr returns the given Attribute as an IPv4 IP address. An error is
// returned if the attribute is not 4 bytes long.
func (a Attribute) IPAddr() (net.IP, error) {
	if len(a) != net.IPv4len {
		return nil, errors.New("invalid length")
	}
	b := make([]byte, net.IPv4len)
	copy(b, []byte(a))
	return b, nil
}

// NewIPAddr returns a new Attribute from the given IP address. An error is
// returned if the given address is not an IPv4 address.
func NewIPAddr(a net.IP) (Attribute, error) {
	a = a.To4()
	if a == nil {
		return nil, errors.New("invalid IPv4 address")
	}
	b := make(Attribute, len(a))
	copy(b, Attribute(a))
	return b, nil
}

// IPv6Addr returns the given Attribute as an IPv6 IP address. An error is
// returned if the attribute is not 16 bytes long.
func (a Attribute) IPv6Addr() (net.IP, error) {
	if len(a) != net.IPv6len {
		return nil, errors.New("invalid length")
	}
	b := make([]byte, net.IPv6len)
	copy(b, []byte(a))
	return b, nil
}

// NewIPv6Addr returns a new Attribute from the given IP address. An error is
// returned if the given address is not an IPv6 address.
func NewIPv6Addr(a net.IP) (Attribute, error) {
	a = a.To16()
	if a == nil {
		return nil, errors.New("invalid IPv6 address")
	}
	b := make(Attribute, len(a))
	copy(b, Attribute(a))
	return b, nil
}

// EAPMessage godoc
func (a Attribute) EAPMessage() (*EapMessage, error) {
	if len(a) < 5 {
		return nil, fmt.Errorf("[EapDecode] protocol error input too small 1")
	}
	length := binary.BigEndian.Uint16(a[2:4])
	if len(a) < int(length) {
		return nil, fmt.Errorf("[EapDecode] protocol error input too small 2")
	}
	eap := &EapMessage{
		Code:       EapCode(a[0]),
		Identifier: uint8(a[1]),
		Type:       EapType(a[4]),
		Data:       a[5:length],
	}
	return eap, nil
}

// NewEAPMessage godoc
func NewEAPMessage(Code EapCode, Identifier uint8, Type EapType, Data Attribute) Attribute {
	v := make([]byte, len(Data)+5)
	v[0] = byte(Code)
	v[1] = byte(Identifier)
	binary.BigEndian.PutUint16(v[2:4], uint16(len(Data)+5))
	v[4] = byte(Type)
	copy(v[5:], Data)
	return Attribute(v)
}
