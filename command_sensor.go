package ipmigo

// Get Sensor Reading Command (Section 35.14)
type GetSensorReadingCommand struct {
	// Request Data
	RsLUN        uint8
	SensorNumber uint8

	// Response Data
	SensorReading      uint8
	ReadingUnavailable bool
	ScanningDisabled   bool
	EventDisabled      bool
	SensorData2        uint8
	SensorData3        uint8
}

func (c *GetSensorReadingCommand) Name() string { return "Get Sensor Reading" }
func (c *GetSensorReadingCommand) Code() uint8  { return 0x2d }

func (c *GetSensorReadingCommand) NetFnRsLUN() NetFnRsLUN {
	return NewNetFnRsLUN(NetFnSensorReq, c.RsLUN)
}

func (c *GetSensorReadingCommand) String() string           { return cmdToJSON(c) }
func (c *GetSensorReadingCommand) Marshal() ([]byte, error) { return []byte{c.SensorNumber}, nil }

func (c *GetSensorReadingCommand) Unmarshal(buf []byte) ([]byte, error) {
	if err := cmdValidateLength(c, buf, 2); err != nil {
		return nil, err
	}
	c.SensorReading = buf[0]
	c.ReadingUnavailable = buf[1]&0x20 != 0
	c.ScanningDisabled = buf[1]&0x40 == 0
	c.EventDisabled = buf[1]&0x80 == 0

	switch l := len(buf); {
	case l == 3:
		c.SensorData2 = buf[2]
	case l >= 4:
		c.SensorData2 = buf[2]
		c.SensorData3 = buf[3]
		return buf[4:], nil
	}
	return nil, nil
}

// Returns `true` if `SensorReading` is valid.
func (c *GetSensorReadingCommand) IsValid() bool {
	return !(c.ReadingUnavailable || c.ScanningDisabled)
}

// Returns the threshold status if sensor is threshold-base.
func (c *GetSensorReadingCommand) ThresholdStatus() ThresholdStatus {
	return NewThresholdStatus(c.SensorData2)
}
