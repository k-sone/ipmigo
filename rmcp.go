package ipmigo

import (
	"encoding/hex"
	"fmt"
)

const (
	rmcpHeaderSize = 4
	rmcpVersion1   = 0x06
	rmcpNoAckSeq   = 0xff // no RMCP ACK (Section 13.2.1)
)

// RMCP(Remote Management Control Protocol) Class of Message (Section 13.1.3)
type rmcpClass uint8

const (
	rmcpClassASF  rmcpClass = 0x06
	rmcpClassIPMI           = 0x07
	rmcpClassOEM            = 0x08
)

func (c rmcpClass) IsAck() bool {
	return c&0x80 != 0
}

func (c rmcpClass) String() string {
	var s string
	switch n := c & 0xf; n {
	case rmcpClassASF:
		s = "ASF"
	case rmcpClassIPMI:
		s = "IPMI"
	case rmcpClassOEM:
		s = "OEM"
	default:
		s = fmt.Sprintf("Reserved(%d)", n)
	}

	if c.IsAck() {
		return "ACK " + s
	} else {
		return "Normal " + s
	}
}

// RMCP Message Header (Section 13.1.3)
type rmcpHeader struct {
	Version  uint8
	Reserved uint8
	Sequence uint8
	Class    rmcpClass
}

func (r *rmcpHeader) Marshal() ([]byte, error) {
	return []byte{
		r.Version,
		r.Reserved,
		r.Sequence,
		byte(r.Class),
	}, nil
}

func (r *rmcpHeader) Unmarshal(buf []byte) ([]byte, error) {
	if len(buf) < rmcpHeaderSize {
		return nil, &MessageError{
			Message: fmt.Sprintf("Invalid RMCP header size : %d", len(buf)),
			Detail:  hex.EncodeToString(buf),
		}
	}

	r.Version = buf[0]
	r.Reserved = buf[1]
	r.Sequence = buf[2]
	r.Class = rmcpClass(buf[3])

	return buf[rmcpHeaderSize:], nil
}

func (r *rmcpHeader) String() string {
	return fmt.Sprintf(
		`{"Version":%d,"Reserved":%d,"Sequence":%d,"Class":"%s"}`,
		r.Version, r.Reserved, r.Sequence, r.Class)
}

func newRMCPHeaderForIPMI() *rmcpHeader {
	return &rmcpHeader{
		Version:  rmcpVersion1,
		Sequence: rmcpNoAckSeq,
		Class:    rmcpClassIPMI,
	}
}
