package ipmigo

import (
	"bytes"
	"fmt"
)

// IPMI LAN Packet (Section 13.6)
type ipmiPacket struct {
	RMCPHeader    *rmcpHeader
	SessionHeader sessionHeader
	PayloadBytes  []byte
	Request       request  // Only exists if packet is a request
	Response      response // Only exists if packet is a response
}

func (p *ipmiPacket) IsRequest() bool {
	return p.Request != nil
}

func (p *ipmiPacket) Marshal() (b []byte, err error) {
	var buf bytes.Buffer
	// RMCP Header
	if b, err = p.RMCPHeader.Marshal(); err != nil {
		return
	}
	buf.Write(b)

	// IPMP Session Header
	if b, err = p.SessionHeader.Marshal(); err != nil {
		return
	}
	buf.Write(b)

	// IPMI Payload
	buf.Write(p.PayloadBytes)

	return buf.Bytes(), nil
}

func (p *ipmiPacket) Unmarshal(buf []byte) ([]byte, error) {
	p.PayloadBytes = buf
	return nil, nil
}

func (p *ipmiPacket) String() string {
	if p.IsRequest() {
		return fmt.Sprintf(`{"RMCPHeader":%s,"SessionHeader":%s,"Request":%s}`,
			p.RMCPHeader, p.SessionHeader, p.Request)
	} else {
		return fmt.Sprintf(`{"RMCPHeader":%s,"SessionHeader":%s,"Response":%s}`,
			p.RMCPHeader, p.SessionHeader, p.Response)
	}
}
