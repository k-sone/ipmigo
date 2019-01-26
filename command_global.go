package ipmigo

// Get Device ID Command (Section 20.1)
type GetDeviceIDCommand struct {
	// Response Data
	DeviceID              uint8
	DeviceRevision        uint8
	DeviceProvidesSDRs    bool
	DeviceAvailable       bool
	FirmwareMajorRevision uint8
	FirmwareMinorRevision uint8
	IPMIVersion           uint8
	SupportDeviceSensor   bool
	SupportDeviceSDRRepo  bool
	SupportDeviceSEL      bool
	SupportDeviceFRU      bool
	SupportDeviceChassis  bool
	// Other fields are omitted because it is not used
}

func (c *GetDeviceIDCommand) Name() string             { return "Get Device ID" }
func (c *GetDeviceIDCommand) Code() uint8              { return 0x01 }
func (c *GetDeviceIDCommand) NetFnRsLUN() NetFnRsLUN   { return NewNetFnRsLUN(NetFnAppReq, 0) }
func (c *GetDeviceIDCommand) String() string           { return cmdToJSON(c) }
func (c *GetDeviceIDCommand) Marshal() ([]byte, error) { return []byte{}, nil }

func (c *GetDeviceIDCommand) Unmarshal(buf []byte) ([]byte, error) {
	if err := cmdValidateLength(c, buf, 11); err != nil {
		return nil, err
	}
	c.DeviceID = buf[0]
	c.DeviceRevision = buf[1] & 0x0f
	c.DeviceProvidesSDRs = buf[1]&0x80 != 0
	c.DeviceAvailable = buf[2]&0x80 == 0
	c.FirmwareMajorRevision = buf[2] & 0x7f
	c.FirmwareMinorRevision = buf[3]
	c.IPMIVersion = buf[4]
	c.SupportDeviceSensor = buf[5]&0x01 != 0
	c.SupportDeviceSDRRepo = buf[5]&0x02 != 0
	c.SupportDeviceSEL = buf[5]&0x04 != 0
	c.SupportDeviceFRU = buf[5]&0x08 != 0
	c.SupportDeviceChassis = buf[5]&0x80 != 0

	if l := len(buf); l < 15 {
		return buf[11:], nil
	} else {
		return buf[15:], nil
	}
	return nil, nil
}
