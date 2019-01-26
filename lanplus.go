package ipmigo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"net"
)

const (
	consoleID uint32 = 0x49504d49 // 'IPMI'

	sessionHeaderV2_0Size = 12 // When payload type is not OEM
)

type sessionHeaderV2_0 struct {
	authType      authType
	payloadType   payloadType
	id            uint32
	sequence      uint32
	payloadLength uint16
}

func (s *sessionHeaderV2_0) ID() uint32               { return s.id }
func (s *sessionHeaderV2_0) AuthType() authType       { return s.authType }
func (s *sessionHeaderV2_0) PayloadType() payloadType { return s.payloadType }
func (s *sessionHeaderV2_0) SetEncrypted(b bool)      { s.payloadType.SetEncrypted(b) }
func (s *sessionHeaderV2_0) SetAuthenticated(b bool)  { s.payloadType.SetAuthenticated(b) }
func (s *sessionHeaderV2_0) PayloadLength() int       { return int(s.payloadLength) }
func (s *sessionHeaderV2_0) SetPayloadLength(n int)   { s.payloadLength = uint16(n) }

func (s *sessionHeaderV2_0) Marshal() ([]byte, error) {
	buf := make([]byte, sessionHeaderV2_0Size)
	buf[0] = byte(s.authType)
	buf[1] = byte(s.payloadType)
	binary.LittleEndian.PutUint32(buf[2:], s.id)
	binary.LittleEndian.PutUint32(buf[6:], s.sequence)
	binary.LittleEndian.PutUint16(buf[10:], s.payloadLength)
	return buf, nil
}

func (s *sessionHeaderV2_0) Unmarshal(buf []byte) ([]byte, error) {
	if len(buf) < sessionHeaderV2_0Size {
		return nil, &MessageError{
			Message: fmt.Sprintf("Invalid IPMI 2.0 session header size : %d", len(buf)),
			Detail:  hex.EncodeToString(buf),
		}
	}
	s.authType = authType(buf[0])
	s.payloadType = payloadType(buf[1])
	s.id = binary.LittleEndian.Uint32(buf[2:])
	s.sequence = binary.LittleEndian.Uint32(buf[6:])
	s.payloadLength = binary.LittleEndian.Uint16(buf[10:])
	return buf[sessionHeaderV2_0Size:], nil
}

func (s *sessionHeaderV2_0) String() string {
	return fmt.Sprintf(`{"AuthType":"%s","PayLoadType":%d,"ID":%d,"Sequence":%d,"PayloadLength":%d}`,
		s.authType, s.payloadType, s.id, s.sequence, s.payloadLength)
}

type sessionV2_0 struct {
	conn     net.Conn
	args     *Arguments
	id       uint32 // Session ID
	sequence uint32 // Session Sequence Number
	rqSeq    uint8  // Command Sequence Number
	k1       []byte // Integrity Key
	k2       []byte // Cipher Key
}

func (s *sessionV2_0) ActiveSession() bool {
	return s.id > 0
}

func (s *sessionV2_0) Header(p payloadType) sessionHeader {
	return &sessionHeaderV2_0{
		authType:    authTypeRMCPPlus,
		id:          s.id,
		sequence:    s.NextSequence(),
		payloadType: p,
	}
}

func (s *sessionV2_0) Ping() error {
	conn, err := net.DialTimeout(s.args.Network, s.args.Address, s.args.Timeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	return ping(conn, s.args.Timeout)
}

func (s *sessionV2_0) Open() error {
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

func (s *sessionV2_0) openSession() error {
	// 1. Get Channel Authentication Capabilities

	// Send in 1.5 packet format to query any server
	s1 := &sessionV1_5{args: s.args, conn: s.conn}
	cac := newChannelAuthCapCommand(V2_0, s.args.PrivilegeLevel)
	if _, err := s1.execute(cac); err != nil {
		// Retry, without requesting IPMI V2
		cac = newChannelAuthCapCommand(V1_5, s.args.PrivilegeLevel)
		if _, err := s1.execute(cac); err != nil {
			return err
		}
	}

	if !cac.IsSupportedAuthType(authTypeRMCPPlus) {
		return &MessageError{
			Message: "Not Support RMCP+",
			Detail:  cac.String(),
		}
	}

	// 2. Open Session Request
	priv := s.args.PrivilegeLevel
	if priv == PrivilegeAdministrator {
		// Request the highest level matching proposed algorithms (lanplus.c L2809)
		priv = PrivilegeLevel(0)
	}

	var pkt *ipmiPacket
	err := retry(int(s.args.Retries), func() (e error) {
		req := &ipmiPacket{
			RMCPHeader:    newRMCPHeaderForIPMI(),
			SessionHeader: s.Header(payloadTypeRMCPOpenReq),
			Request: &openSessionRequest{
				ConsoleID:      consoleID,
				PrivilegeLevel: priv,
				CipherSuiteID:  s.args.CipherSuiteID,
			},
		}
		pkt, e = s.SendPacket(req)
		return
	})
	if err != nil {
		return err
	}

	osr, ok := pkt.Response.(*openSessionResponse)
	if !ok {
		return &MessageError{
			Message: "Received an unexpected message (Open Session Response)",
			Detail:  pkt.String(),
		}
	}
	if osr.StatusCode != rakpStatusNoErrors {
		return &MessageError{
			Message: fmt.Sprintf("Error in Open Session Response : %s", osr.StatusCode),
			Detail:  pkt.String(),
		}
	}
	if consoleID != osr.ConsoleID {
		return &MessageError{
			Message: fmt.Sprintf("Mismatch console session ID in Open Session Response : 0x%x - 0x%x",
				consoleID, osr.ConsoleID),
			Detail: pkt.String(),
		}
	}
	if reqSuite := cipherSuiteIDs[s.args.CipherSuiteID]; !reqSuite.Equal(&osr.CipherSuite) {
		return &MessageError{
			Message: fmt.Sprintf("Mismatch cipher suite : %s - %s", reqSuite, osr.CipherSuite),
			Detail:  pkt.String(),
		}
	}

	// 3. Exchange information(RAKP Message 1,2)
	r1 := &rakpMessage1{
		ManagedID:       osr.ManagedID,
		PrivilegeLevel:  s.args.PrivilegeLevel,
		PrivilegeLookup: false,
		Username:        s.args.Username,
	}

	err = retry(int(s.args.Retries), func() (e error) {
		req := &ipmiPacket{
			RMCPHeader:    newRMCPHeaderForIPMI(),
			SessionHeader: s.Header(payloadTypeRAKP1),
			Request:       r1,
		}
		pkt, e = s.SendPacket(req)
		return
	})
	if err != nil {
		return err
	}

	r2, ok := pkt.Response.(*rakpMessage2)
	if !ok {
		return &MessageError{
			Message: "Received an unexpected message (RAKP 2)",
			Detail:  pkt.String(),
		}
	}
	if r2.StatusCode != rakpStatusNoErrors {
		return &MessageError{
			Message: fmt.Sprintf("Error in RAKP 2 : %s", r2.StatusCode),
			Detail:  pkt.String(),
		}
	}
	if consoleID != r2.ConsoleID {
		return &MessageError{
			Message: fmt.Sprintf("Mismatch console session ID in RAKP 2 : 0x%x - 0x%x", consoleID, r2.ConsoleID),
			Detail:  pkt.String(),
		}
	}
	if err = r2.ValidateAuthCode(s.args, r1); err != nil {
		return err
	}

	// 4. Activate session(RAKP Message 3,4)
	r3 := &rakpMessage3{
		StatusCode: rakpStatusNoErrors,
		ManagedID:  osr.ManagedID,
	}
	r3.GenerateAuthCode(s.args, r1, r2)
	r3.GenerateSIK(s.args, r1, r2)
	r3.GenerateK1(s.args)
	r3.GenerateK2(s.args)

	err = retry(int(s.args.Retries), func() (e error) {
		req := &ipmiPacket{
			RMCPHeader:    newRMCPHeaderForIPMI(),
			SessionHeader: s.Header(payloadTypeRAKP3),
			Request:       r3,
		}
		pkt, e = s.SendPacket(req)
		return
	})
	if err != nil {
		return err
	}

	r4, ok := pkt.Response.(*rakpMessage4)
	if !ok {
		return &MessageError{
			Message: "Received an unexpected message (RAKP 4)",
			Detail:  pkt.String(),
		}
	}
	if r4.StatusCode != rakpStatusNoErrors {
		return &MessageError{
			Message: fmt.Sprintf("Error in RAKP 4 : %s", r2.StatusCode),
			Detail:  pkt.String(),
		}
	}
	if consoleID != r4.ConsoleID {
		return &MessageError{
			Message: fmt.Sprintf("Mismatch console session ID in RAKP 4 : 0x%x - 0x%x", consoleID, r4.ConsoleID),
			Detail:  pkt.String(),
		}
	}
	if err = r4.ValidateAuthCode(s.args, r1, r2, r3); err != nil {
		return err
	}

	// Set session ID
	s.id = osr.ManagedID
	s.k1 = r3.K1[:]
	s.k2 = r3.K2[:]

	// Set session privilege level
	if l := s.args.PrivilegeLevel; l > PrivilegeUser {
		if _, err := s.execute(newSetSessionPrivilegeCommand(l)); err != nil {
			return &MessageError{
				Cause:   err,
				Message: fmt.Sprintf("Unable to set session privilege level to %s", l),
			}
		}
	}

	return nil
}

func (s *sessionV2_0) Close() error {
	if s.ActiveSession() {
		if err := s.Execute(newCloseSessionCommand(s.id)); err != nil {
			return err
		}

		s.id = 0
		s.sequence = 0
		s.rqSeq = 0
		s.k1 = nil
		s.k2 = nil
	}

	if c := s.conn; c != nil {
		if err := c.Close(); err != nil {
			return err
		}
		s.conn = nil
	}

	return nil
}

func (s *sessionV2_0) Execute(cmd Command) error {
	if err := s.Open(); err != nil {
		return err
	}

	if _, err := s.execute(cmd); err != nil {
		return err
	}
	return nil
}

func (s *sessionV2_0) execute(cmd Command) (response, error) {
	var res *ipmiPacket
	err := retry(int(s.args.Retries), func() (e error) {
		req := &ipmiPacket{
			RMCPHeader:    newRMCPHeaderForIPMI(),
			SessionHeader: s.Header(payloadTypeIPMI),
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

func (s *sessionV2_0) NextSequence() uint32 {
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

func (s *sessionV2_0) NextRqSeq() uint8 {
	n := s.rqSeq
	s.rqSeq++
	if s.rqSeq >= 64 {
		s.rqSeq = 0
	}
	return n << 2
}

func (s *sessionV2_0) SendPacket(req *ipmiPacket) (*ipmiPacket, error) {
	if buf, err := req.Request.Marshal(); err == nil {
		req.PayloadBytes = buf
		req.SessionHeader.SetPayloadLength(len(buf))
	} else {
		return nil, err
	}

	if s.ActiveSession() {
		// Encrypt the payload
		if requiredConfidentiality(s.args.CipherSuiteID) {
			req.SessionHeader.SetEncrypted(true)
			if buf, err := encryptPayload(req.PayloadBytes, s.k2); err == nil {
				req.PayloadBytes = buf
				req.SessionHeader.SetPayloadLength(len(buf))
			} else {
				return nil, err
			}
		}
		// Append the session trailer
		if requiredIntegrity(s.args.CipherSuiteID) {
			// Trailer's source is the session header and payload
			req.SessionHeader.SetAuthenticated(true)
			if msg, err := req.SessionHeader.Marshal(); err == nil {
				trailer := makeTrailer(append(msg, req.PayloadBytes...), s.k1)
				req.PayloadBytes = append(req.PayloadBytes, trailer...)
			} else {
				return nil, err
			}
		}
	}

	res, msg, err := sendMessage(s.conn, req, s.args.Timeout)
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

	if s.ActiveSession() {
		if id := pkt.SessionHeader.ID(); consoleID != id {
			return nil, &MessageError{
				Message: fmt.Sprintf("Mismatch console session ID : 0x%x - 0x%x", consoleID, id),
				Detail:  pkt.String(),
			}
		}

		if requiredIntegrity(s.args.CipherSuiteID) {
			if !pkt.SessionHeader.PayloadType().Authenticated() {
				return nil, &MessageError{
					Message: "Response message is not authenticated",
					Detail:  pkt.String(),
				}
			}
			if err := validateTrailer(msg[rmcpHeaderSize:], s.k1); err != nil {
				return nil, err
			}
		}

		if requiredConfidentiality(s.args.CipherSuiteID) {
			if !pkt.SessionHeader.PayloadType().Encrypted() {
				return nil, &MessageError{
					Message: "Response message is not encrypted",
					Detail:  pkt.String(),
				}
			}
			if buf, err := decryptPayload(pkt.PayloadBytes, s.k2); err == nil {
				pkt.PayloadBytes = buf
				pkt.SessionHeader.SetPayloadLength(len(buf))
			} else {
				return nil, err
			}
		}
	}

	// Response unmarshal
	if _, err := pkt.Response.Unmarshal(pkt.PayloadBytes); err != nil {
		return nil, err
	}

	return pkt, nil
}

func (s *sessionV2_0) String() string {
	return fmt.Sprintf(`{ID:%d,"Sequence":%d,"RqSeq":%d,"K1":"%s","K2":"%s"}`,
		s.id, s.sequence, s.rqSeq, hex.EncodeToString(s.k1), hex.EncodeToString(s.k2))
}

func newSessionV2_0(args *Arguments) session {
	return &sessionV2_0{
		args: args,
	}
}

// Section 13.29
func encryptPayload(src, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:16]) // AES-128
	if err != nil {
		return nil, err
	}

	// Add the pad and the pad length
	srcLen := len(src)
	padLen := 0
	if mod := (srcLen + 1) % aes.BlockSize; mod != 0 {
		padLen = aes.BlockSize - mod
	}
	input := make([]byte, srcLen+padLen+1)
	copy(input, src)

	for i := 0; i < padLen; i++ {
		input[srcLen+i] = byte(i + 1)
	}
	input[srcLen+padLen] = byte(padLen)

	// Initialization vector
	dst := make([]byte, aes.BlockSize+len(input))
	iv := dst[:aes.BlockSize]
	if _, err = rand.Read(iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(dst[aes.BlockSize:], input)

	return dst, nil
}

func decryptPayload(src, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:16]) // AES-128
	if err != nil {
		return nil, err
	}

	if l := len(src); l < aes.BlockSize || l%aes.BlockSize != 0 {
		return nil, &MessageError{
			Message: fmt.Sprintf("Payload is not the specified length : %d", l),
		}
	}

	dst := make([]byte, len(src)-aes.BlockSize)
	iv, data := src[:aes.BlockSize], src[aes.BlockSize:]
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(dst, data)

	padLen := int(dst[len(dst)-1])
	return dst[:len(dst)-padLen-1], nil
}

func makeTrailer(src, key []byte) []byte {
	// Session Trailer (Table 13-8)
	// +---------------+
	// | Integrity PAD |  n bytes
	// | Pad Length    |  1 byte
	// | Next Header   |  1 byte  (0x07)
	// | AuthCode      | 12 bytes
	// +---------------+
	srcLen := len(src)
	padLen := 0
	if mod := (srcLen + 1 + 1 + 12) % 4; mod != 0 {
		padLen = 4 - mod
	}

	data := make([]byte, srcLen+padLen+2+12)
	copy(data, src)

	for i := 0; i < padLen; i++ {
		data[srcLen+i] = 0xff // Integrity Pad byte
	}
	data[srcLen+padLen] = byte(padLen)
	data[srcLen+padLen+1] = 0x07 // Next Header

	mac := hmac.New(sha1.New, key)
	mac.Write(data[:srcLen+padLen+2])
	// Use the first 12 bytes of the authcode
	authCode := mac.Sum(nil)
	copy(data[srcLen+padLen+2:], authCode[:12])

	return data[srcLen:]
}

func validateTrailer(src, key []byte) error {
	if l := len(src); l < 12 {
		return &MessageError{
			Message: fmt.Sprintf("Payload does not contain auth code : %d", l),
		}
	}

	authCode := src[len(src)-12:]
	mac := hmac.New(sha1.New, key)
	mac.Write(src[:len(src)-12])

	if generated := mac.Sum(nil); !bytes.Equal(authCode, generated[:12]) {
		return &MessageError{
			Message: fmt.Sprintf("Received message with invalid authcode : %s - %s",
				hex.EncodeToString(authCode), hex.EncodeToString(generated)),
			Detail: hex.EncodeToString(src),
		}
	}

	return nil
}
