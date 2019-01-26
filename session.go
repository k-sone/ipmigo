package ipmigo

import (
	"fmt"
)

// Payload Type (Section 13.27.3)
type payloadType uint8

const (
	payloadTypeIPMI        payloadType = 0x00
	payloadTypeSOL                     = 0x01
	payloadTypeOEM                     = 0x02
	payloadTypeRMCPOpenReq             = 0x10
	payloadTypeRMCPOpenRes             = 0x11
	payloadTypeRAKP1                   = 0x12
	payloadTypeRAKP2                   = 0x13
	payloadTypeRAKP3                   = 0x14
	payloadTypeRAKP4                   = 0x15
)

// Return a payloadType without encrypt/authenticate flags
func (p payloadType) Pure() payloadType {
	return payloadType(byte(p) & 0x3f)
}

func (p *payloadType) SetEncrypted(b bool) {
	if b {
		*p = payloadType(byte(*p) | 0x80)
	} else {
		*p = payloadType(byte(*p) & 0x7f)
	}
}

func (p payloadType) Encrypted() bool {
	return p&0x80 != 0
}

func (p *payloadType) SetAuthenticated(b bool) {
	if b {
		*p = payloadType(byte(*p) | 0x40)
	} else {
		*p = payloadType(byte(*p) & 0xbf)
	}
}

func (p payloadType) Authenticated() bool {
	return p&0x40 != 0
}

// Authentication Type (Section 13.6)
type authType uint8

const (
	authTypeNone     authType = 0x0
	authTypeMD2               = 0x1
	authTypeMD5               = 0x2
	authTypePassword          = 0x4
	authTypeOEM               = 0x5
	authTypeRMCPPlus          = 0x6
)

func (a authType) String() string {
	switch a {
	case authTypeNone:
		return "NONE"
	case authTypeMD2:
		return "MD2"
	case authTypeMD5:
		return "MD5"
	case authTypePassword:
		return "PASSWORD"
	case authTypeOEM:
		return "OEM"
	case authTypeRMCPPlus:
		return "RMCP+"
	default:
		return fmt.Sprintf("Reserved(%d)", a)
	}
}

type sessionHeader interface {
	ID() uint32
	AuthType() authType
	PayloadType() payloadType
	SetEncrypted(bool)
	SetAuthenticated(bool)
	PayloadLength() int
	SetPayloadLength(int)
	Marshal() ([]byte, error)
	Unmarshal([]byte) ([]byte, error)
	String() string
}

type session interface {
	Ping() error
	Open() error
	Close() error
	Execute(Command) error
}
