package ipmigo

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
)

// Get Channel Authentication Capabilities Command (Section 22.13)
type channelAuthCapCommand struct {
	// Request Data
	ReqChannelNumber uint8
	PrivilegeLevel   PrivilegeLevel

	// Response Data
	ResChannelNumber uint8
	AuthTypeSupport  uint8
	AuthStatus       uint8
	// Other fields are omitted because it is not used
}

func (c *channelAuthCapCommand) Name() string           { return "Get Channel Authentication Capabilities" }
func (c *channelAuthCapCommand) Code() uint8            { return 0x38 }
func (c *channelAuthCapCommand) NetFnRsLUN() NetFnRsLUN { return NewNetFnRsLUN(NetFnAppReq, 0) }
func (c *channelAuthCapCommand) String() string         { return cmdToJSON(c) }

func (c *channelAuthCapCommand) Marshal() ([]byte, error) {
	return []byte{c.ReqChannelNumber, byte(c.PrivilegeLevel)}, nil
}

func (c *channelAuthCapCommand) Unmarshal(buf []byte) ([]byte, error) {
	if err := cmdValidateLength(c, buf, 8); err != nil {
		return nil, err
	}
	c.ResChannelNumber = buf[0]
	c.AuthTypeSupport = buf[1]
	c.AuthStatus = buf[2]
	return buf[8:], nil
}

func (c *channelAuthCapCommand) IsSupportedAuthType(t authType) bool {
	if t == authTypeRMCPPlus {
		return (c.AuthTypeSupport & 0x80) != 0
	} else {
		return c.AuthTypeSupport&(1<<t) != 0
	}
}

func newChannelAuthCapCommand(v Version, l PrivilegeLevel) *channelAuthCapCommand {
	var n uint8 = 0x0e // Retrieve information for channel
	if v == V2_0 {
		n |= 0x80 // For RMCP+
	}

	return &channelAuthCapCommand{
		ReqChannelNumber: n,
		PrivilegeLevel:   l,
	}
}

// Set Session Privilege Level Command(Section 22.18)
type setSessionPrivilegeCommand struct {
	// Request Data
	RequestedLevel PrivilegeLevel

	// Response Data
	NewLevel PrivilegeLevel
}

func (c *setSessionPrivilegeCommand) Name() string           { return "Set Session Privilege Level" }
func (c *setSessionPrivilegeCommand) Code() uint8            { return 0x3b }
func (c *setSessionPrivilegeCommand) NetFnRsLUN() NetFnRsLUN { return NewNetFnRsLUN(NetFnAppReq, 0) }
func (c *setSessionPrivilegeCommand) String() string         { return cmdToJSON(c) }

func (c *setSessionPrivilegeCommand) Marshal() ([]byte, error) {
	return []byte{byte(c.RequestedLevel)}, nil
}

func (c *setSessionPrivilegeCommand) Unmarshal(buf []byte) ([]byte, error) {
	if err := cmdValidateLength(c, buf, 1); err != nil {
		return nil, err
	}
	c.NewLevel = PrivilegeLevel(buf[0])
	return buf[1:], nil
}

func newSetSessionPrivilegeCommand(l PrivilegeLevel) *setSessionPrivilegeCommand {
	return &setSessionPrivilegeCommand{RequestedLevel: l}
}

// Close Session Command (Section 22.19)
type closeSessionCommand struct {
	// Request Data
	SessionID uint32
}

func (c *closeSessionCommand) Name() string           { return "Close Session" }
func (c *closeSessionCommand) Code() uint8            { return 0x3c }
func (c *closeSessionCommand) NetFnRsLUN() NetFnRsLUN { return NewNetFnRsLUN(NetFnAppReq, 0) }
func (c *closeSessionCommand) String() string         { return cmdToJSON(c) }

func (c *closeSessionCommand) Marshal() ([]byte, error) {
	id := c.SessionID
	return []byte{byte(id), byte(id >> 8), byte(id >> 16), byte(id >> 24)}, nil
}

func (c *closeSessionCommand) Unmarshal(buf []byte) ([]byte, error) {
	return buf, nil
}

func newCloseSessionCommand(id uint32) *closeSessionCommand {
	return &closeSessionCommand{SessionID: id}
}

// Get Session Info Command (Section 22.20)
type GetSessionInfoCommand struct {
	// Request Data
	SessionIndex uint8  // Request Type (0x00: Current , 0xN: Nth active, 0xfe: By handle , 0xff: By ID)
	SessionID    uint32 // Session ID or Handle

	// Response Data
	SessionHandle      uint8
	SessionSlotCount   uint8
	ActiveSessionCount uint8
	UserID             uint8
	PrivilegeLevel     PrivilegeLevel
	ChannelType        uint8 // (0x00: IPMI v1.5, 0x01: IPMI v2.0)
	ChannelNumber      uint8
	ConsoleIP          net.IP
	ConsoleMAC         net.HardwareAddr
	ConsolePort        uint16
}

func (c *GetSessionInfoCommand) Name() string { return "Get Session Info" }
func (c *GetSessionInfoCommand) Code() uint8  { return 0x3d }

func (c *GetSessionInfoCommand) NetFnRsLUN() NetFnRsLUN {
	return NewNetFnRsLUN(NetFnAppReq, 0)
}

func (c *GetSessionInfoCommand) String() string { return cmdToJSON(c) }

func (c *GetSessionInfoCommand) Marshal() ([]byte, error) {
	switch c.SessionIndex {
	case 0xff:
		id := c.SessionID
		return []byte{0xff, byte(id), byte(id >> 8), byte(id >> 16), byte(id >> 24)}, nil
	case 0xfe:
		return []byte{0xfe, byte(c.SessionID)}, nil
	case 0x00:
		fallthrough
	default:
		return []byte{c.SessionIndex}, nil
	}
}

func (c *GetSessionInfoCommand) Unmarshal(buf []byte) ([]byte, error) {
	if l := len(buf); l != 3 && l < 18 {
		return nil, &MessageError{
			Message: fmt.Sprintf("Invalid %s Response size : %d", c.Name(), l),
			Detail:  hex.EncodeToString(buf),
		}
	}
	c.SessionHandle = buf[0]
	c.SessionSlotCount = buf[1] & 0x3f
	c.ActiveSessionCount = buf[2] & 0x3f

	if len(buf) == 3 {
		// No an active session corresponding to the given session index
		return nil, nil
	}

	c.UserID = buf[3] & 0x3f
	c.PrivilegeLevel = PrivilegeLevel(buf[4] & 0x0f)
	c.ChannelType = (buf[5] & 0xf0) >> 4
	c.ChannelNumber = buf[5] & 0x0f

	// Supports only the 802.3 LAN channel type
	c.ConsoleIP = net.IPv4(buf[6], buf[7], buf[8], buf[9])
	c.ConsoleMAC = make(net.HardwareAddr, 6)
	copy(c.ConsoleMAC, buf[10:16])
	c.ConsolePort = binary.BigEndian.Uint16(buf[16:18])

	return buf[18:], nil
}
