package ipmigo

import (
	"encoding/binary"
)

// Get SDR Repository Info Command (Section 33.9)
type GetSDRRepositoryInfoCommand struct {
	// Response Data
	SDRVersion  uint8 // (0x01: IPMIv1.0, 0x51: IPMIv1.5, 0x02: IPMIv2.0)
	RecordCount uint16
	// Other fields are omitted because it is not used
}

func (c *GetSDRRepositoryInfoCommand) Name() string { return "Get SDR Repository Info" }
func (c *GetSDRRepositoryInfoCommand) Code() uint8  { return 0x20 }

func (c *GetSDRRepositoryInfoCommand) NetFnRsLUN() NetFnRsLUN {
	return NewNetFnRsLUN(NetFnStorageReq, 0)
}

func (c *GetSDRRepositoryInfoCommand) String() string           { return cmdToJSON(c) }
func (c *GetSDRRepositoryInfoCommand) Marshal() ([]byte, error) { return []byte{}, nil }

func (c *GetSDRRepositoryInfoCommand) Unmarshal(buf []byte) ([]byte, error) {
	if err := cmdValidateLength(c, buf, 14); err != nil {
		return nil, err
	}
	c.SDRVersion = buf[0]
	c.RecordCount = binary.LittleEndian.Uint16(buf[1:3])
	return buf[14:], nil
}

// Reserve SDR Repository Command (Section 33.11)
type ReserveSDRRepositoryCommand struct {
	// Response Data
	ReservationID uint16
}

func (c *ReserveSDRRepositoryCommand) Name() string { return "Reserve SDR Repository" }
func (c *ReserveSDRRepositoryCommand) Code() uint8  { return 0x22 }

func (c *ReserveSDRRepositoryCommand) NetFnRsLUN() NetFnRsLUN {
	return NewNetFnRsLUN(NetFnStorageReq, 0)
}

func (c *ReserveSDRRepositoryCommand) String() string           { return cmdToJSON(c) }
func (c *ReserveSDRRepositoryCommand) Marshal() ([]byte, error) { return []byte{}, nil }

func (c *ReserveSDRRepositoryCommand) Unmarshal(buf []byte) ([]byte, error) {
	if err := cmdValidateLength(c, buf, 2); err != nil {
		return nil, err
	}
	c.ReservationID = binary.LittleEndian.Uint16(buf)
	return buf[2:], nil
}

// Get SDR Command (Section 33.12)
type GetSDRCommand struct {
	// Request Data
	ReservationID uint16
	RecordID      uint16
	RecordOffset  uint8
	ReadBytes     uint8

	// Response Data
	NextRecordID uint16
	RecordData   []byte
}

func (c *GetSDRCommand) Name() string           { return "Get SDR" }
func (c *GetSDRCommand) Code() uint8            { return 0x23 }
func (c *GetSDRCommand) NetFnRsLUN() NetFnRsLUN { return NewNetFnRsLUN(NetFnStorageReq, 0) }
func (c *GetSDRCommand) String() string         { return cmdToJSON(c) }

func (c *GetSDRCommand) Marshal() ([]byte, error) {
	return []byte{byte(c.ReservationID), byte(c.ReservationID >> 8), byte(c.RecordID), byte(c.RecordID >> 8),
		byte(c.RecordOffset), byte(c.ReadBytes)}, nil
}

func (c *GetSDRCommand) Unmarshal(buf []byte) ([]byte, error) {
	if err := cmdValidateLength(c, buf, 2); err != nil {
		return nil, err
	}

	c.NextRecordID = binary.LittleEndian.Uint16(buf)
	buf = buf[2:]
	if l := len(buf); l <= int(c.ReadBytes) {
		c.RecordData = make([]byte, l)
		copy(c.RecordData, buf)
		return nil, nil
	} else {
		c.RecordData = make([]byte, c.ReadBytes)
		copy(c.RecordData, buf)
		return buf[c.ReadBytes:], nil
	}
}
