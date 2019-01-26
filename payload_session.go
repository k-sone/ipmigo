package ipmigo

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

const (
	openSessionRequestSize  = 32
	openSessionResponseSize = 36
	rakpMessage1Size        = 44
	rakpMessage2Size        = 40
	rakpMessage3Size        = 8
	rakpMessage4Size        = 8

	integrityCheckSize = 12        // Supported HMAC-SHA1-96 only (Section 13.28.1)
	authCodeSize       = sha1.Size // Supported RAKP-HMAC-SHA1 only (Section 13.28.1)
	sikSize            = sha1.Size
)

var const1 = [sikSize]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
var const2 = [sikSize]byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}

// Authentication Algorithm (Section 13.28)
type authAlgorithm uint8

const (
	authRakpNone authAlgorithm = iota
	authRakpHmacSHA1
	authRakpHmacMD5
)

func (a authAlgorithm) String() string {
	switch a {
	case authRakpNone:
		return "RAKP-none"
	case authRakpHmacSHA1:
		return "RAKP-HMAC-SHA1"
	case authRakpHmacMD5:
		return "RAKP-HMAC-MD5"
	default:
		return fmt.Sprintf("Unknown(%d)", a)
	}
}

// Integrity Algorithm (Section 13.28.4)
type integrityAlgorithm uint8

const (
	integrityNone integrityAlgorithm = iota
	integrityHmacSHA1_96
	integrityHmacMD5_128
	integrityMD5_128
)

func (a integrityAlgorithm) String() string {
	switch a {
	case integrityNone:
		return "None"
	case integrityHmacSHA1_96:
		return "HMAC-SHA1-96"
	case integrityHmacMD5_128:
		return "HMAC-MD5-128"
	case integrityMD5_128:
		return "MD5-128"
	default:
		return fmt.Sprintf("Unknown(%d)", a)
	}
}

// Confidentiality Algorithm (Section 13.28.5)
type cryptAlgorithm uint8

const (
	cryptNone cryptAlgorithm = iota
	cryptAesCBC_128
	cryptXRC4_128
	cryptXRC4_40
)

func (a cryptAlgorithm) String() string {
	switch a {
	case cryptNone:
		return "None"
	case cryptAesCBC_128:
		return "AES-CBC-128"
	case cryptXRC4_128:
		return "xRC4-128"
	case cryptXRC4_40:
		return "xRC4-128"
	default:
		return fmt.Sprintf("Unknown(%d)", a)
	}
}

// Cipher Suite (Section 22.15.2)
type cipherSuite struct {
	Auth      authAlgorithm
	Integrity integrityAlgorithm
	Crypt     cryptAlgorithm
}

func (c *cipherSuite) Equal(o *cipherSuite) bool {
	return c.Auth == o.Auth && c.Integrity == o.Integrity && c.Crypt == o.Crypt
}

func (c *cipherSuite) String() string {
	return fmt.Sprintf(`{"Auth":"%s","Integrity":"%s","Crypt":"%s"}`,
		c.Auth, c.Integrity, c.Crypt)
}

// Cipher Suite IDs (Table 22-20)
var cipherSuiteIDs []cipherSuite = []cipherSuite{
	cipherSuite{authRakpNone, integrityNone, cryptNone},
	cipherSuite{authRakpHmacSHA1, integrityNone, cryptNone},
	cipherSuite{authRakpHmacSHA1, integrityHmacSHA1_96, cryptNone},
	cipherSuite{authRakpHmacSHA1, integrityHmacSHA1_96, cryptAesCBC_128},
	cipherSuite{authRakpHmacSHA1, integrityHmacSHA1_96, cryptXRC4_128},
	cipherSuite{authRakpHmacSHA1, integrityHmacSHA1_96, cryptXRC4_40},
	cipherSuite{authRakpHmacMD5, integrityNone, cryptNone},
	cipherSuite{authRakpHmacMD5, integrityHmacMD5_128, cryptNone},
	cipherSuite{authRakpHmacMD5, integrityHmacMD5_128, cryptAesCBC_128},
	cipherSuite{authRakpHmacMD5, integrityHmacMD5_128, cryptXRC4_128},
	cipherSuite{authRakpHmacMD5, integrityHmacMD5_128, cryptXRC4_40},
	cipherSuite{authRakpHmacMD5, integrityMD5_128, cryptNone},
	cipherSuite{authRakpHmacMD5, integrityMD5_128, cryptAesCBC_128},
	cipherSuite{authRakpHmacMD5, integrityMD5_128, cryptXRC4_128},
	cipherSuite{authRakpHmacMD5, integrityMD5_128, cryptXRC4_40},
}

// RMCP+ Open Session Request (Section 13.17)
type openSessionRequest struct {
	MessageTag     uint8
	ConsoleID      uint32 // Remote console session ID
	PrivilegeLevel PrivilegeLevel
	CipherSuiteID  uint
}

func (o *openSessionRequest) Marshal() ([]byte, error) {
	cipher := cipherSuiteIDs[o.CipherSuiteID]

	buf := make([]byte, openSessionRequestSize)
	buf[0] = o.MessageTag
	buf[1] = byte(o.PrivilegeLevel)
	//buf[2] = 0 // reserved
	//buf[3] = 0 // reserved

	// Our session ID
	binary.LittleEndian.PutUint32(buf[4:], o.ConsoleID)

	// Authentication payload
	buf[8] = 0 // authentication payload type(0)
	//buf[9] = 0  // reserved
	//buf[10] = 0 // reserved
	buf[11] = 8 // payload length(8)
	buf[12] = byte(cipher.Auth)
	//buf[13] = 0 // reserved
	//buf[14] = 0 // reserved
	//buf[15] = 0 // reserved

	// Integrity payload
	buf[16] = 1 // integrity payload type(1)
	//buf[17] = 0 // reserved
	//buf[18] = 0 // reserved
	buf[19] = 8 // payload length(8)
	buf[20] = byte(cipher.Integrity)
	//buf[21] = 0 // reserved
	//buf[22] = 0 // reserved
	//buf[23] = 0 // reserved

	// Confidentiality payload
	buf[24] = 2 // confidentiality payload type(2)
	//buf[25] = 0 // reserved
	//buf[26] = 0 // reserved
	buf[27] = 8 // payload length(8)
	buf[28] = byte(cipher.Crypt)
	//buf[29] = 0 // reserved
	//buf[30] = 0 // reserved
	//buf[31] = 0 // reserved

	return buf, nil
}

func (o *openSessionRequest) String() string {
	return fmt.Sprintf(`{"MessageTag":%d,"ConsoleID":%d,"PrivilegeLevel":"%s","CipherSuiteID":%d}`,
		o.MessageTag, o.ConsoleID, o.PrivilegeLevel, o.CipherSuiteID)
}

// RMCP+ and RAKP Message Status Code (Section13.24)
type rakpStatusCode uint8

const (
	rakpStatusNoErrors rakpStatusCode = iota
	rakpStatusInsufficientResource
	rakpStatusInvalidSessionID
	rakpStatusInvalidPayloadType
	rakpStatusInvalidAuthAlgorithm
	rakpStatusInvalidIntegrityAlgorithm
	rakpStatusNoMatchingAuthPayload
	rakpStatusNoMatchingIntegrityPayload
	rakpStatusInactiveSessionID
	rakpStatusInvalidRole
	rakpStatusUnauthorizedRoleRequested
	rakpStatusInsufficientResources
	rakpStatusInvalidNameLength
	rakpStatusUnauthorizedName
	rakpStatusUnauthorizedGUID
	rakpStatusInvalidIntegrityCheck
	rakpStatusInvalidConfidentialityAlgorithm
	rakpStatusNoCipherSuiteMatch
	rakpStatusIllegalParameter
)

func (c rakpStatusCode) String() string {
	switch c {
	case rakpStatusNoErrors:
		return "No errors"
	case rakpStatusInsufficientResource:
		return "Insufficient resources to create a session"
	case rakpStatusInvalidSessionID:
		return "Invalid Session ID"
	case rakpStatusInvalidPayloadType:
		return "Invalid payload type"
	case rakpStatusInvalidAuthAlgorithm:
		return "Invalid authentication algorithm"
	case rakpStatusInvalidIntegrityAlgorithm:
		return "Invalid integrity algorithm"
	case rakpStatusNoMatchingAuthPayload:
		return "No matching authentication payload"
	case rakpStatusNoMatchingIntegrityPayload:
		return "No matching integrity payload"
	case rakpStatusInactiveSessionID:
		return "Inactive Session ID"
	case rakpStatusInvalidRole:
		return "Invalid role"
	case rakpStatusUnauthorizedRoleRequested:
		return "Unauthorized role or privilege level requested"
	case rakpStatusInsufficientResources:
		return "Insufficient resources to create a session at the requested role"
	case rakpStatusInvalidNameLength:
		return "Invalid name length"
	case rakpStatusUnauthorizedName:
		return "Unauthorized name"
	case rakpStatusUnauthorizedGUID:
		return "Unauthorized GUID"
	case rakpStatusInvalidIntegrityCheck:
		return "Invalid integrity check value"
	case rakpStatusInvalidConfidentialityAlgorithm:
		return "Invalid confidentiality algorithm"
	case rakpStatusNoCipherSuiteMatch:
		return "No Cipher Suite match with proposed security algorithms"
	case rakpStatusIllegalParameter:
		return "Illegal or unrecognized parameter"
	default:
		return fmt.Sprintf("Unknown(%d)", c)
	}
}

// RMCP+ Open Session Response (Section 13.18)
type openSessionResponse struct {
	MessageTag     uint8
	StatusCode     rakpStatusCode
	PrivilegeLevel PrivilegeLevel
	ConsoleID      uint32 // Remote console session ID
	ManagedID      uint32 // Managed system session ID
	CipherSuite    cipherSuite
}

func (o *openSessionResponse) Unmarshal(buf []byte) ([]byte, error) {
	if l := len(buf); l < openSessionResponseSize {
		buf = append(buf, make([]byte, openSessionResponseSize-l)...)
	}

	o.MessageTag = buf[0]
	o.StatusCode = rakpStatusCode(buf[1])
	o.PrivilegeLevel = PrivilegeLevel(buf[2])
	o.ConsoleID = binary.LittleEndian.Uint32(buf[4:])
	o.ManagedID = binary.LittleEndian.Uint32(buf[8:])
	o.CipherSuite.Auth = authAlgorithm(buf[16])
	o.CipherSuite.Integrity = integrityAlgorithm(buf[24])
	o.CipherSuite.Crypt = cryptAlgorithm(buf[32])
	return buf[openSessionResponseSize:], nil
}

func (o *openSessionResponse) String() string {
	return fmt.Sprintf(
		`{"MessageTag":%d,"StatusCode":"%s","PrivilegeLevel":"%s",`+
			`"ConsoleID":%d,"ManagedID":%d,"CipherSuite":%s}`,
		o.MessageTag, o.StatusCode, o.PrivilegeLevel, o.ConsoleID, o.ManagedID, &o.CipherSuite)
}

// RAKP Message 1 (Section 13.20)
type rakpMessage1 struct {
	MessageTag      uint8
	ManagedID       uint32    // Managed system sesssion ID
	ConsoleRand     [16]uint8 // Remote console random number
	PrivilegeLevel  PrivilegeLevel
	PrivilegeLookup bool // Use username and privilege for lookup
	Username        string
}

func (r *rakpMessage1) RequestedRole() byte {
	b := byte(r.PrivilegeLevel)
	if !r.PrivilegeLookup {
		b |= 0x10
	}
	return b
}

func (r *rakpMessage1) Marshal() ([]byte, error) {
	buf := make([]byte, rakpMessage1Size)
	buf[0] = r.MessageTag
	// buf[1] = 0 // reserved
	// buf[2] = 0 // reserved
	// buf[3] = 0 // reserved
	binary.LittleEndian.PutUint32(buf[4:], r.ManagedID)

	// 16 byte random number
	if _, err := rand.Read(r.ConsoleRand[:]); err != nil {
		return nil, err
	}
	copy(buf[8:24], r.ConsoleRand[:])

	buf[24] = r.RequestedRole()
	// buf[25] = 0 // reserved
	// buf[26] = 0 // reserved

	// Username
	ulen := len(r.Username)
	buf[27] = byte(ulen)
	copy(buf[28:], r.Username)

	return buf[:28+ulen], nil
}

func (r *rakpMessage1) String() string {
	return fmt.Sprintf(
		`{"MessageTag":%d,"ManagedID":%d,"ConsoleRand":"%s",`+
			`"PrivilegeLevel":"%s","PrivilegeLookup":%t,"Username":"%s"}`,
		r.MessageTag, r.ManagedID, hex.EncodeToString(r.ConsoleRand[:]), r.PrivilegeLevel,
		r.PrivilegeLookup, r.Username)
}

// RAKP Message 2 (Section 13.21)
type rakpMessage2 struct {
	MessageTag          uint8
	StatusCode          rakpStatusCode
	ConsoleID           uint32    // Remote console session ID
	ManagedRand         [16]uint8 // Managed system random number
	ManagedGUID         [16]uint8 // Managed system GUID
	KeyExchangeAuthCode [authCodeSize]byte
}

func (r *rakpMessage2) ValidateAuthCode(args *Arguments, r1 *rakpMessage1) error {
	if !requiredAuthentication(args.CipherSuiteID) {
		return nil
	}

	key := make([]byte, passwordMaxLengthV2_0)
	copy(key, args.Password)

	data := make([]byte, 58+len(r1.Username))
	binary.LittleEndian.PutUint32(data, r.ConsoleID)      // SIDm
	binary.LittleEndian.PutUint32(data[4:], r1.ManagedID) // SIDc
	copy(data[8:], r1.ConsoleRand[:])                     // Rm
	copy(data[24:], r.ManagedRand[:])                     // Rc
	copy(data[40:], r.ManagedGUID[:])                     // GUIDc
	data[56] = r1.RequestedRole()                         // ROLEm
	data[57] = byte(len(r1.Username))                     // ULENGTHm
	copy(data[58:], r1.Username)                          // UNAMEm

	mac := hmac.New(sha1.New, key)
	mac.Write(data)

	if s := mac.Sum(nil); !hmac.Equal(r.KeyExchangeAuthCode[:], s) {
		return &MessageError{
			Message: fmt.Sprintf("RAKP 2 HMAC is invalid : %s - %s",
				hex.EncodeToString(r.KeyExchangeAuthCode[:]), hex.EncodeToString(s)),
			Detail: r.String(),
		}
	}
	return nil
}

func (r *rakpMessage2) Unmarshal(buf []byte) ([]byte, error) {
	size := rakpMessage2Size
	if l := len(buf); l < size {
		buf = append(buf, make([]byte, size-l)...)
	}

	r.MessageTag = buf[0]
	r.StatusCode = rakpStatusCode(buf[1])
	r.ConsoleID = binary.LittleEndian.Uint32(buf[4:])
	copy(r.ManagedRand[:], buf[8:24])
	copy(r.ManagedGUID[:], buf[24:40])
	copy(r.KeyExchangeAuthCode[:], buf[40:])

	return buf[size:], nil
}

func (r *rakpMessage2) String() string {
	return fmt.Sprintf(
		`{"MessageTag":%d,"StatusCode":"%s","ConsoleID":%d,`+
			`"ManagedRand":"%s","ManagedGUID":"%s","KeyExchangeAuthCode":"%s"}`,
		r.MessageTag, r.StatusCode, r.ConsoleID, hex.EncodeToString(r.ManagedRand[:]),
		hex.EncodeToString(r.ManagedGUID[:]), hex.EncodeToString(r.KeyExchangeAuthCode[:]))
}

// RAKP Message 3 (Section 13.22)
type rakpMessage3 struct {
	MessageTag          uint8
	StatusCode          rakpStatusCode
	ManagedID           uint32
	KeyExchangeAuthCode [authCodeSize]byte

	SIK [sikSize]byte // Session Integrity Key
	K1  [sikSize]byte
	K2  [sikSize]byte
}

func (r *rakpMessage3) GenerateAuthCode(args *Arguments, r1 *rakpMessage1, r2 *rakpMessage2) {
	if !requiredAuthentication(args.CipherSuiteID) {
		return
	}

	key := make([]byte, passwordMaxLengthV2_0)
	copy(key, args.Password)

	data := make([]byte, 22+len(r1.Username))
	copy(data, r2.ManagedRand[:])                          // Rc
	binary.LittleEndian.PutUint32(data[16:], r2.ConsoleID) // SIDm
	data[20] = r1.RequestedRole()                          // ROLEm
	data[21] = byte(len(r1.Username))                      // ULENGTHm
	copy(data[22:], r1.Username)                           // UNAMEm

	mac := hmac.New(sha1.New, key)
	mac.Write(data)
	copy(r.KeyExchangeAuthCode[:], mac.Sum(nil))
}

func (r *rakpMessage3) GenerateSIK(args *Arguments, r1 *rakpMessage1, r2 *rakpMessage2) {
	if !requiredAuthentication(args.CipherSuiteID) {
		return
	}

	// Not support KG key
	key := make([]byte, passwordMaxLengthV2_0)
	copy(key, args.Password)

	data := make([]byte, 34+len(r1.Username))
	copy(data, r1.ConsoleRand[:])      // Rm
	copy(data[16:], r2.ManagedRand[:]) // Rc
	data[32] = r1.RequestedRole()      // ROLEm
	data[33] = byte(len(r1.Username))  // ULENGTHm
	copy(data[34:], r1.Username)       // UNAMEm

	mac := hmac.New(sha1.New, key)
	mac.Write(data)
	copy(r.SIK[:], mac.Sum(nil))
}

func (r *rakpMessage3) GenerateK1(args *Arguments) {
	if !requiredAuthentication(args.CipherSuiteID) {
		return
	}

	key := make([]byte, len(r.SIK))
	copy(key, r.SIK[:])

	mac := hmac.New(sha1.New, key)
	mac.Write(const1[:])
	copy(r.K1[:], mac.Sum(nil))
}

func (r *rakpMessage3) GenerateK2(args *Arguments) {
	if !requiredAuthentication(args.CipherSuiteID) {
		return
	}

	key := make([]byte, len(r.SIK))
	copy(key, r.SIK[:])

	mac := hmac.New(sha1.New, key)
	mac.Write(const2[:])
	copy(r.K2[:], mac.Sum(nil))
}

func (r *rakpMessage3) Marshal() ([]byte, error) {
	size := rakpMessage3Size + len(r.KeyExchangeAuthCode)

	buf := make([]byte, size)
	buf[0] = r.MessageTag
	buf[1] = byte(r.StatusCode)
	// buf[2] = 0 // reserved
	// buf[3] = 0 // reserved
	binary.LittleEndian.PutUint32(buf[4:], r.ManagedID)
	copy(buf[8:], r.KeyExchangeAuthCode[:])

	return buf, nil
}

func (r *rakpMessage3) String() string {
	return fmt.Sprintf(
		`{"MessageTag":%d,"StatusCode":"%s","ManagedID":%d,"KeyExchangeAuthCode":"%s"}`,
		r.MessageTag, r.StatusCode, r.ManagedID, hex.EncodeToString(r.KeyExchangeAuthCode[:]))
}

type rakpMessage4 struct {
	MessageTag          uint8
	StatusCode          rakpStatusCode
	ConsoleID           uint32 // Remote console session ID
	IntegrityCheckValue [integrityCheckSize]byte
}

func (r *rakpMessage4) ValidateAuthCode(args *Arguments, r1 *rakpMessage1, r2 *rakpMessage2, r3 *rakpMessage3) error {
	if !requiredAuthentication(args.CipherSuiteID) {
		return nil
	}

	key := make([]byte, len(r3.SIK))
	copy(key, r3.SIK[:])

	data := make([]byte, 36)
	copy(data, r1.ConsoleRand[:])                          // Rm
	binary.LittleEndian.PutUint32(data[16:], r1.ManagedID) // SIDc
	copy(data[20:], r2.ManagedGUID[:])                     // GUIDc

	mac := hmac.New(sha1.New, key)
	mac.Write(data)
	if s := mac.Sum(nil)[:integrityCheckSize]; !hmac.Equal(r.IntegrityCheckValue[:], s) {
		return &MessageError{
			Message: fmt.Sprintf("RAKP 4 HMAC is invalid : %s - %s",
				hex.EncodeToString(r.IntegrityCheckValue[:]), hex.EncodeToString(s)),
			Detail: r.String(),
		}
	}
	return nil
}

func (r *rakpMessage4) Unmarshal(buf []byte) ([]byte, error) {
	size := rakpMessage4Size + len(r.IntegrityCheckValue)
	if l := len(buf); l < size {
		buf = append(buf, make([]byte, size-l)...)
	}

	r.MessageTag = buf[0]
	r.StatusCode = rakpStatusCode(buf[1])
	r.ConsoleID = binary.LittleEndian.Uint32(buf[4:])
	copy(r.IntegrityCheckValue[:], buf[8:])

	return buf[size:], nil
}

func (r *rakpMessage4) String() string {
	return fmt.Sprintf(
		`{"MessageTag":%d,"StatusCode":"%s","ConsoleID":%d,"IntegrityCheckValue":"%s"}`,
		r.MessageTag, r.StatusCode, r.ConsoleID, hex.EncodeToString(r.IntegrityCheckValue[:]))
}

func requiredAuthentication(cid uint) bool {
	switch suite := cipherSuiteIDs[cid]; suite.Auth {
	default:
		panic(`ipmigo: unsupported authentication algorithm - ` + suite.Auth.String())
	case authRakpNone:
		return false
	case authRakpHmacSHA1:
		return true
	}
}

func requiredIntegrity(cid uint) bool {
	switch suite := cipherSuiteIDs[cid]; suite.Integrity {
	default:
		panic(`ipmigo: unsupported integrity algorithm - ` + suite.Integrity.String())
	case integrityNone:
		return false
	case integrityHmacSHA1_96:
		return true
	}
}

func requiredConfidentiality(cid uint) bool {
	switch suite := cipherSuiteIDs[cid]; suite.Crypt {
	default:
		panic(`ipmigo: unsupported confidentiality algorithm - ` + suite.Crypt.String())
	case cryptNone:
		return false
	case cryptAesCBC_128:
		return true
	}
}
