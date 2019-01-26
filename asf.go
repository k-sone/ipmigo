package ipmigo

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"time"
)

const (
	asfHeaderSize = 8
	pongBodySize  = 16
	asfIANA       = 0x000011be
)

type asfType uint8

const (
	asfTypePing = 0x80
	asfTypePong = 0x40
)

func (t asfType) String() string {
	switch t {
	case asfTypePing:
		return "Ping"
	case asfTypePong:
		return "Pong"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

type asfHeader struct {
	IANA     uint32
	Type     asfType
	Tag      uint8
	Reserved uint8
	Length   uint8
}

func (a *asfHeader) Marshal() ([]byte, error) {
	buf := make([]byte, asfHeaderSize)
	binary.BigEndian.PutUint32(buf, a.IANA)
	buf[4] = byte(a.Type)
	buf[5] = a.Tag
	buf[6] = a.Reserved
	buf[7] = a.Length
	return buf, nil
}

func (a *asfHeader) Unmarshal(buf []byte) ([]byte, error) {
	if len(buf) < asfHeaderSize {
		return nil, &MessageError{
			Message: fmt.Sprintf("Invalid ASF header size : %d", len(buf)),
			Detail:  hex.EncodeToString(buf),
		}
	}

	a.IANA = binary.BigEndian.Uint32(buf)
	a.Type = asfType(buf[4])
	a.Tag = buf[5]
	a.Reserved = buf[6]
	a.Length = buf[7]

	return buf[8:], nil
}

func (a *asfHeader) String() string {
	return fmt.Sprintf(
		`{"IANA":%d,"Type":"%s","Tag":%d,"Reserved":%d,"Length":%d}`,
		a.IANA, a.Type, a.Tag, a.Reserved, a.Length)
}

// RMCP/ASF Ping Message (Section 13.2.3)
type pingMessage struct {
	RMCPHeader *rmcpHeader
	ASFHeader  *asfHeader
}

func (p *pingMessage) Marshal() ([]byte, error) {
	buf1, err := p.RMCPHeader.Marshal()
	if err != nil {
		return nil, err
	}
	buf2, err := p.ASFHeader.Marshal()
	if err != nil {
		return nil, err
	}
	return append(buf1, buf2...), nil
}

func (p *pingMessage) String() string {
	return fmt.Sprintf(`{"RMCPHeader":%s,"ASFHeader":%s}`, p.RMCPHeader, p.ASFHeader)
}

func newPingMessage() *pingMessage {
	return &pingMessage{
		RMCPHeader: &rmcpHeader{
			Version:  rmcpVersion1,
			Sequence: rmcpNoAckSeq,
			Class:    rmcpClassASF,
		},
		ASFHeader: &asfHeader{
			IANA: asfIANA,
			Type: asfTypePing,
		},
	}
}

// RMCP/ASF Pong Message (Section 13.2.4)
type pongMessage struct {
	rmcpHeader  *rmcpHeader
	asfHeader   *asfHeader
	IANA        uint32
	OEM         uint32
	SupEntities uint8
	SupInteract uint8
	Reserved    [6]byte
}

func (p *pongMessage) SupportedIPMI() bool {
	return p.SupEntities&0x80 != 0
}

func (p *pongMessage) Unmarshal(buf []byte) ([]byte, error) {
	if len(buf) < pongBodySize {
		return nil, &MessageError{
			Message: fmt.Sprintf("Invalid Pong body size : %d", len(buf)),
			Detail:  hex.EncodeToString(buf),
		}
	}

	p.IANA = binary.BigEndian.Uint32(buf)
	p.OEM = binary.BigEndian.Uint32(buf[4:])
	p.SupEntities = buf[8]
	p.SupInteract = buf[9]
	copy(p.Reserved[:], buf[10:])

	return buf[pongBodySize:], nil
}

func (p *pongMessage) String() string {
	return fmt.Sprintf(
		`{"RMCPHeader":%s,"ASFHeader":%s,"IANA":%d,"OEM":%d,`+
			`"SupEntities":%d,"SupInteract":%d,"Reserved":"%s"}`,
		p.rmcpHeader, p.asfHeader, p.IANA, p.OEM, p.SupEntities, p.SupInteract,
		hex.EncodeToString(p.Reserved[:]))
}

func ping(conn net.Conn, timeout time.Duration) error {
	res, _, err := sendMessage(conn, newPingMessage(), timeout)
	if err != nil {
		return err
	}

	pong, ok := res.(*pongMessage)
	if !ok {
		return &MessageError{
			Message: "Received an unexpected message (Ping)",
			Detail:  res.String(),
		}
	}
	if !pong.SupportedIPMI() {
		return ErrNotSupportedIPMI
	}

	return nil
}
