package ipmigo

import (
	"encoding/binary"
	"time"
)

// Get Chassis Status Command (Section 28.2)
type GetChassisStatusCommand struct {
	// Response Data
	PowerIsOn               bool
	PowerOverload           bool
	PowerInterlock          bool
	PowerFault              bool
	PowerControlFault       bool
	PowerRestorePolicy      uint8 // (See Table 28-3)
	LastPowerEventACFailed  bool
	LastPowerEventOverload  bool
	LastPowerEventInterlock bool
	LastPowerEventFault     bool
	LastPowerEventCommand   bool
	ChassisIntrusionActive  bool
	FrontPanelLockoutActive bool
	DriveFault              bool
	CoolingFanFault         bool
}

func (c *GetChassisStatusCommand) Name() string             { return "Get Chassis Status" }
func (c *GetChassisStatusCommand) Code() uint8              { return 0x01 }
func (c *GetChassisStatusCommand) NetFnRsLUN() NetFnRsLUN   { return NewNetFnRsLUN(NetFnChassisReq, 0) }
func (c *GetChassisStatusCommand) String() string           { return cmdToJSON(c) }
func (c *GetChassisStatusCommand) Marshal() ([]byte, error) { return []byte{}, nil }

func (c *GetChassisStatusCommand) Unmarshal(buf []byte) ([]byte, error) {
	if err := cmdValidateLength(c, buf, 3); err != nil {
		return nil, err
	}
	c.PowerIsOn = buf[0]&0x01 != 0
	c.PowerOverload = buf[0]&0x02 != 0
	c.PowerInterlock = buf[0]&0x04 != 0
	c.PowerFault = buf[0]&0x08 != 0
	c.PowerControlFault = buf[0]&0x10 != 0
	c.PowerRestorePolicy = buf[0] & 0x60 >> 5

	c.LastPowerEventACFailed = buf[1]&0x01 != 0
	c.LastPowerEventOverload = buf[1]&0x02 != 0
	c.LastPowerEventInterlock = buf[1]&0x04 != 0
	c.LastPowerEventFault = buf[1]&0x08 != 0
	c.LastPowerEventCommand = buf[1]&0x10 != 0

	c.ChassisIntrusionActive = buf[2]&0x01 != 0
	c.FrontPanelLockoutActive = buf[2]&0x02 != 0
	c.DriveFault = buf[2]&0x04 != 0
	c.CoolingFanFault = buf[2]&0x08 != 0
	return nil, nil
}

// Get System Restart Cause Command (Section 28.11)
type GetSystemRestartCauseCommand struct {
	// Response Data
	RestartCause uint8 // (See Table 28-11)
}

func (c *GetSystemRestartCauseCommand) Name() string { return "Get System Restart Cause" }
func (c *GetSystemRestartCauseCommand) Code() uint8  { return 0x07 }

func (c *GetSystemRestartCauseCommand) NetFnRsLUN() NetFnRsLUN {
	return NewNetFnRsLUN(NetFnChassisReq, 0)
}

func (c *GetSystemRestartCauseCommand) String() string           { return cmdToJSON(c) }
func (c *GetSystemRestartCauseCommand) Marshal() ([]byte, error) { return []byte{}, nil }

func (c *GetSystemRestartCauseCommand) Unmarshal(buf []byte) ([]byte, error) {
	if err := cmdValidateLength(c, buf, 1); err != nil {
		return nil, err
	}
	c.RestartCause = buf[0]
	return buf[1:], nil
}

// Get POH Counter Command (Section 28.14)
type GetPOHCounterCommand struct {
	// Response Data
	MinutesPerCount uint8
	Counter         uint32
}

func (c *GetPOHCounterCommand) Name() string             { return "Get POH Counter" }
func (c *GetPOHCounterCommand) Code() uint8              { return 0x0f }
func (c *GetPOHCounterCommand) NetFnRsLUN() NetFnRsLUN   { return NewNetFnRsLUN(NetFnChassisReq, 0) }
func (c *GetPOHCounterCommand) String() string           { return cmdToJSON(c) }
func (c *GetPOHCounterCommand) Marshal() ([]byte, error) { return []byte{}, nil }

func (c *GetPOHCounterCommand) Unmarshal(buf []byte) ([]byte, error) {
	if err := cmdValidateLength(c, buf, 5); err != nil {
		return nil, err
	}
	c.MinutesPerCount = uint8(buf[0])
	c.Counter = binary.LittleEndian.Uint32(buf[1:5])
	return buf[5:], nil
}

func (c *GetPOHCounterCommand) PowerOnHours() time.Duration {
	return time.Duration(c.MinutesPerCount) * time.Duration(c.Counter) * time.Minute
}
