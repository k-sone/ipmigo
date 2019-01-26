package ipmigo

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
)

const (
	sessionHeaderV1_5Size         = 10 // When authentication type is none
	sessionHeaderV1_5SizeWithAuth = 26
)

type sessionHeaderV1_5 struct {
	authType      authType
	sequence      uint32
	id            uint32
	payloadLength uint8
	authCode      [16]byte // Present when authentication type is not none
}

func (s *sessionHeaderV1_5) ID() uint32               { return s.id }
func (s *sessionHeaderV1_5) AuthType() authType       { return s.authType }
func (s *sessionHeaderV1_5) PayloadType() payloadType { return payloadTypeIPMI }
func (s *sessionHeaderV1_5) SetEncrypted(b bool)      { /* noop */ }
func (s *sessionHeaderV1_5) SetAuthenticated(b bool)  { /* noop */ }
func (s *sessionHeaderV1_5) PayloadLength() int       { return int(s.payloadLength) }
func (s *sessionHeaderV1_5) SetPayloadLength(n int)   { s.payloadLength = uint8(n) }

func (s *sessionHeaderV1_5) Marshal() ([]byte, error) {
	var buf []byte
	if s.authType == authTypeNone {
		buf = make([]byte, sessionHeaderV1_5Size)
	} else {
		buf = make([]byte, sessionHeaderV1_5SizeWithAuth)
		copy(buf[sessionHeaderV1_5Size-1:], s.authCode[:])
	}
	buf[0] = byte(s.authType)
	binary.LittleEndian.PutUint32(buf[1:], s.sequence)
	binary.LittleEndian.PutUint32(buf[5:], s.id)
	buf[len(buf)-1] = byte(s.payloadLength)
	return buf, nil
}

func (s *sessionHeaderV1_5) Unmarshal(buf []byte) ([]byte, error) {
	if len(buf) < sessionHeaderV1_5Size {
		goto ERROR
	}
	s.authType = authType(buf[0])
	s.sequence = binary.LittleEndian.Uint32(buf[1:])
	s.id = binary.LittleEndian.Uint32(buf[5:])

	if s.authType == authTypeNone {
		s.payloadLength = buf[sessionHeaderV1_5Size-1]
		return buf[sessionHeaderV1_5Size:], nil
	}
	if len(buf) >= sessionHeaderV1_5SizeWithAuth {
		copy(s.authCode[:], buf[sessionHeaderV1_5Size-1:])
		s.payloadLength = buf[sessionHeaderV1_5SizeWithAuth-1]
		return buf[sessionHeaderV1_5SizeWithAuth:], nil
	}

ERROR:
	return nil, &MessageError{
		Message: fmt.Sprintf("Invalid IPMI 1.5 session header size : %d", len(buf)),
		Detail:  hex.EncodeToString(buf),
	}
}

func (s *sessionHeaderV1_5) String() string {
	return fmt.Sprintf(`{"AuthType":"%s","Sequence":%d,"ID":%d,"PayloadLength":%d,"AuthCode":"%s"}`,
		s.authType, s.sequence, s.id, s.payloadLength, hex.EncodeToString(s.authCode[:]))
}

type sessionV1_5 struct {
	conn     net.Conn
	args     *Arguments
	authType authType
	id       uint32 // Session ID
	sequence uint32 // Session Sequence Number
	rqSeq    uint8  // Command Sequence Number
}

func (s *sessionV1_5) ActiveSession() bool {
	return s.id > 0
}

func (s *sessionV1_5) Header() sessionHeader {
	hdr := &sessionHeaderV1_5{
		authType: s.authType,
		sequence: s.NextSequence(),
		id:       s.id,
	}
	if s.authType != authTypeNone {
		copy(hdr.authCode[:], []byte(s.args.Password))
	}

	return hdr
}

func (s *sessionV1_5) Ping() error {
	conn, err := net.DialTimeout(s.args.Network, s.args.Address, s.args.Timeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	return ping(conn, s.args.Timeout)
}

func (s *sessionV1_5) Open() error {
	if s.conn != nil {
		return nil
	}

	err := retry(int(s.args.Retries), func() error {
		conn, e := net.DialTimeout(s.args.Network, s.args.Address, s.args.Timeout)
		if e == nil {
			s.conn = conn
		}
		return e
	})
	if err != nil {
		return err
	}

	err = s.openSession()
	if err != nil {
		defer s.Close()
	}
	return err
}

func (s *sessionV1_5) openSession() error {
	// 1. RMCP Presence Ping
	err := retry(int(s.args.Retries), func() error {
		return ping(s.conn, s.args.Timeout)
	})
	if err != nil {
		return err
	}

	// 2. Get Channel Authentication Capabilities
	cac := newChannelAuthCapCommand(V1_5, s.args.PrivilegeLevel)
	if _, err := s.execute(cac); err != nil {
		return err
	}

	for _, t := range []authType{authTypeMD5, authTypePassword, authTypeNone} {
		if cac.IsSupportedAuthType(t) {
			s.authType = t
			break
		}
		if t == authTypeNone {
			return &MessageError{
				Message: "No supported authentication types found",
				Detail:  cac.String(),
			}
		}
	}

	// 3. Get Session Challenge

	// 4. Activate Session

	// TODO
	return errors.New("Not implemented yet")
}

func (s *sessionV1_5) Close() error {
	if s.ActiveSession() {
		s.id = 0
		s.sequence = 0
		s.rqSeq = 0
		s.authType = authTypeNone
	}

	if c := s.conn; c != nil {
		if err := c.Close(); err != nil {
			return err
		}
		s.conn = nil
	}
	return nil
}

func (s *sessionV1_5) Execute(cmd Command) error {
	if err := s.Open(); err != nil {
		return err
	}

	if _, err := s.execute(cmd); err != nil {
		return err
	}
	return nil
}

func (s *sessionV1_5) execute(cmd Command) (response, error) {
	var res *ipmiPacket
	err := retry(int(s.args.Retries), func() (e error) {
		req := &ipmiPacket{
			RMCPHeader:    newRMCPHeaderForIPMI(),
			SessionHeader: s.Header(),
			Request: &ipmiRequestMessage{
				RsAddr:  bmcSlaveAddress,
				RqAddr:  remoteSWID,
				RqSeq:   s.NextRqSeq(),
				Command: cmd,
			},
		}
		res, e = s.SendPacket(req)
		return
	})
	if err != nil {
		return nil, err
	}

	rsm, ok := res.Response.(*ipmiResponseMessage)
	if !ok {
		return nil, &MessageError{
			Message: "Received an unexpected message (Command)",
			Detail:  res.String(),
		}
	}

	if rsm.CompletionCode != CompletionOK {
		return nil, &CommandError{
			CompletionCode: rsm.CompletionCode,
			Command:        cmd,
		}
	}
	if _, err = cmd.Unmarshal(rsm.Data); err != nil {
		return nil, err
	}

	return res, nil
}

func (s *sessionV1_5) NextSequence() uint32 {
	if s.ActiveSession() {
		switch s.sequence {
		case math.MaxUint32:
			// wrap around
			s.sequence = 1
		default:
			s.sequence++
		}
	}
	return s.sequence
}

func (s *sessionV1_5) NextRqSeq() uint8 {
	n := s.rqSeq
	s.rqSeq++
	if s.rqSeq >= 64 {
		s.rqSeq = 0
	}
	return n << 2
}

func (s *sessionV1_5) SendPacket(req *ipmiPacket) (*ipmiPacket, error) {
	if buf, err := req.Request.Marshal(); err == nil {
		req.PayloadBytes = buf
		req.SessionHeader.SetPayloadLength(len(buf))
	} else {
		return nil, err
	}

	res, _, err := sendMessage(s.conn, req, s.args.Timeout)
	if err != nil {
		return nil, err
	}
	pkt, ok := res.(*ipmiPacket)
	if !ok {
		return nil, &MessageError{
			Message: "Received an unexpected message (IPMI)",
			Detail:  res.String(),
		}
	}

	// Response unmarshal
	if _, err := pkt.Response.Unmarshal(pkt.PayloadBytes); err != nil {
		return nil, err
	}

	return pkt, nil
}

func (s *sessionV1_5) String() string {
	return fmt.Sprintf(`{ID:%d,"Sequence":%d,"RqSeq":%d,"AuthType":"%s"}`,
		s.id, s.sequence, s.rqSeq, s.authType)
}

func newSessionV1_5(args *Arguments) session {
	return &sessionV1_5{
		args: args,
	}
}
