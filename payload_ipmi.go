package ipmigo

import (
	"encoding/hex"
	"fmt"
)

const (
	ipmiResponseMessageMinSize = 8
)

// Network Function Codes (Section 5.1)
type NetFn uint8

const (
	NetFnChassisReq NetFn = iota
	NetFnChassisRes
	NetFnBridgeReq
	NetFnBridgeRes
	NetFnSensorReq
	NetFnSensorRes
	NetFnAppReq
	NetFnAppRes
	NetFnFirmwareReq
	NetFnFirmwareRes
	NetFnStorageReq
	NetFnStorageRes
	NetFnTransportReq
	NetFnTransportRes
)

// Network Function and Logical Unit Number
type NetFnRsLUN uint8

func (n NetFnRsLUN) NetFn() NetFn {
	return NetFn(byte(n) >> 2)
}

func (n NetFnRsLUN) RsLUN() uint8 {
	return byte(n) & 0x3
}

func NewNetFnRsLUN(netFn NetFn, rsLUN uint8) NetFnRsLUN {
	return NetFnRsLUN(uint8(netFn)<<2 | (rsLUN & 0x3))
}

// IPMI LAN Request Message (Section 13.8)
type ipmiRequestMessage struct {
	RsAddr  uint8
	RqAddr  uint8
	RqSeq   uint8
	Command Command
}

func (m *ipmiRequestMessage) Marshal() ([]byte, error) {
	data, err := m.Command.Marshal()
	if err != nil {
		return nil, err
	}

	// +--------------------+
	// | rsAddr             | 6 bytes
	// | netFn/rsLUN        |
	// | 1st checksum       |
	// | rqAddr             |
	// | rqSeq              |
	// | cmd                |
	// +--------------------+
	// | request data bytes |
	// +--------------------+
	// | 2nd checksum       | 1 bytes
	// +--------------------+
	buf := make([]byte, len(data)+7)
	buf[0] = m.RsAddr
	buf[1] = byte(m.Command.NetFnRsLUN())
	buf[2] = checksum(buf[0:2])
	buf[3] = m.RqAddr
	buf[4] = m.RqSeq
	buf[5] = m.Command.Code()
	copy(buf[6:], data)
	buf[len(buf)-1] = checksum(buf[3 : len(buf)-1])

	return buf, nil
}

func (m *ipmiRequestMessage) String() string {
	return fmt.Sprintf(
		`{"RsAddr":%d,"RqAddr":%d,"RqSeq":%d,"Command":%s}`,
		m.RsAddr, m.RqAddr, m.RqSeq, m.Command)
}

// IPMI LAN Response Message (Section 13.8)
type ipmiResponseMessage struct {
	RqAddr         uint8
	NetFnRsRUN     NetFnRsLUN
	RsAddr         uint8
	RqSeq          uint8
	Code           uint8
	CompletionCode CompletionCode
	Data           []byte
}

func (m *ipmiResponseMessage) Unmarshal(buf []byte) ([]byte, error) {
	if len(buf) < ipmiResponseMessageMinSize {
		return nil, &MessageError{
			Message: fmt.Sprintf("Invalid IPMI response size : %d", len(buf)),
			Detail:  hex.EncodeToString(buf),
		}
	}

	// +---------------------+
	// | rqAddr              | 7 bytes
	// | netFn/rsLUN         |
	// | 1st checksum        |
	// | rsAddr              |
	// | rqSeq               |
	// | cmd                 |
	// | completion code     |
	// +---------------------+
	// | response data bytes |
	// +---------------------+
	// | 2nd checksum        | 1 bytes
	// +---------------------+
	if csum := checksum(buf[0:2]); csum != buf[2] {
		return nil, &MessageError{
			Message: fmt.Sprintf("Invalid IPMI response 1st checksum(%d, %d)", csum, buf[2]),
			Detail:  hex.EncodeToString(buf),
		}
	}
	if csum := checksum(buf[3 : len(buf)-1]); csum != buf[len(buf)-1] {
		return nil, &MessageError{
			Message: fmt.Sprintf("Invalid IPMI response 2nd checksum(%d, %d)", csum, buf[len(buf)-1]),
			Detail:  hex.EncodeToString(buf),
		}
	}

	m.RqAddr = buf[0]
	m.NetFnRsRUN = NetFnRsLUN(buf[1])
	m.RsAddr = buf[3]
	m.RqSeq = buf[4]
	m.Code = buf[5]
	m.CompletionCode = CompletionCode(buf[6])
	m.Data = buf[7 : len(buf)-1]
	return nil, nil
}

func (m *ipmiResponseMessage) String() string {
	return fmt.Sprintf(
		`{"RqAddr":%d,"NetFnRsRUN":%d,"RsAddr":%d,"RqSeq":%d,"Code":%d,"CompletionCode":%d,"Data":"%s"}`,
		m.RqAddr, m.NetFnRsRUN, m.RsAddr, m.RqSeq, m.Code, m.CompletionCode, hex.EncodeToString(m.Data))
}

func checksum(buf []byte) byte {
	var c byte
	for _, x := range buf {
		c += x
	}
	return -c
}
