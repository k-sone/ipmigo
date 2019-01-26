package ipmigo

import (
	"fmt"
	"net"
	"time"
)

const (
	recvBufferSize = 1 << 11
)

type request interface {
	Marshal() (buf []byte, err error)
	String() string
}

type response interface {
	Unmarshal(buf []byte) (rest []byte, err error)
	String() string
}

func unmarshalMessage(buf []byte) (response, []byte, error) {
	rmcp := &rmcpHeader{}
	rest, err := rmcp.Unmarshal(buf)
	if err != nil {
		return nil, nil, err
	}

	switch rmcp.Class {
	default:
		return nil, nil, &MessageError{
			Message: fmt.Sprintf("Unknown RMCP class : %s", rmcp.Class),
			Detail:  rmcp.String(),
		}
	case rmcpClassASF:
		asf := &asfHeader{}
		if rest, err = asf.Unmarshal(rest); err != nil {
			return nil, nil, err
		}

		switch asf.Type {
		case asfTypePong:
			pong := &pongMessage{rmcpHeader: rmcp, asfHeader: asf}
			if rest, err = pong.Unmarshal(rest); err != nil {
				return nil, nil, err
			}
			return pong, rest, nil
		default:
			return nil, nil, &MessageError{
				Message: fmt.Sprintf("Unknown ASF message type : %s", asf.Type),
				Detail:  asf.String(),
			}
		}
	case rmcpClassIPMI:
		var hdr sessionHeader
		if authType(rest[0]) == authTypeRMCPPlus {
			hdr = &sessionHeaderV2_0{}
		} else {
			hdr = &sessionHeaderV1_5{}
		}
		if rest, err = hdr.Unmarshal(rest); err != nil {
			return nil, nil, err
		}

		pkt := &ipmiPacket{
			RMCPHeader:    rmcp,
			SessionHeader: hdr,
		}

		switch hdr.PayloadType().Pure() {
		case payloadTypeIPMI:
			pkt.Response = &ipmiResponseMessage{}
		case payloadTypeRMCPOpenRes:
			pkt.Response = &openSessionResponse{}
		case payloadTypeRAKP2:
			pkt.Response = &rakpMessage2{}
		case payloadTypeRAKP4:
			pkt.Response = &rakpMessage4{}
		default:
			return nil, nil, &MessageError{
				Message: fmt.Sprintf("Unknown IPMI payload type : %s", hdr.PayloadType()),
				Detail:  pkt.String(),
			}
		}

		plen := hdr.PayloadLength()
		if _, err = pkt.Unmarshal(rest[:plen]); err != nil {
			return nil, nil, err
		}

		return pkt, rest[plen:], nil
	}
}

func sendMessage(conn net.Conn, req request, timeout time.Duration) (response, []byte, error) {
	buf, err := req.Marshal()
	if err != nil {
		return nil, nil, err
	}

	deadline := time.Now().Add(timeout)
	if err = conn.SetDeadline(deadline); err != nil {
		return nil, nil, err
	}
	if _, err = conn.Write(buf); err != nil {
		return nil, nil, err
	}

	buf = make([]byte, recvBufferSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, nil, err
	}
	buf = buf[:n]

	res, _, err := unmarshalMessage(buf)
	return res, buf, err
}
