package ipmigo

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
)

const (
	sdrFirstID uint16 = 0x0000
	sdrLastID  uint16 = 0xffff

	sdrIDStringMaxSize  = 16
	sdrHeaderSize       = 5
	sdrDefaultReadBytes = 32

	sdrCommonSensorSize     = 18
	sdrFullSensorSize       = 25 + sdrCommonSensorSize
	sdrFRUDeviceLocatorSize = 11
)

// Sensor Data Record Type
type SDRType uint8

const (
	SDRTypeFullSensor              SDRType = 0x01
	SDRTypeCompactSensor           SDRType = 0x02
	SDRTypeEventOnlySensor         SDRType = 0x03
	SDRTypeEntityAssociation       SDRType = 0x08
	SDRTypeDeviceEntityAssociation SDRType = 0x09
	SDRTypeGenericDeviceLocator    SDRType = 0x10
	SDRTypeFRUDeviceLocator        SDRType = 0x11
	SDRTypeMCDeviceLocator         SDRType = 0x12
	SDRTypeMCConfirmation          SDRType = 0x13
	SDRTypeBMCMessageChannelInfo   SDRType = 0x14
	SDRTypeOEM                     SDRType = 0xc0
)

// Sensor Data Record Header (Section 43)
type sdrHeader struct {
	RecordID       uint16
	SDRVersion     uint8
	RecordType     SDRType
	RemainingBytes uint8
}

func (r *sdrHeader) Unmarshal(buf []byte) ([]byte, error) {
	if l := len(buf); l < sdrHeaderSize {
		return nil, &MessageError{
			Message: fmt.Sprintf("Invalid SDRHeader size : %d/%d", l, sdrHeaderSize),
			Detail:  hex.EncodeToString(buf),
		}
	}

	r.RecordID = binary.LittleEndian.Uint16(buf[:2])
	r.SDRVersion = buf[2]
	r.RecordType = SDRType(buf[3])
	r.RemainingBytes = buf[4]
	return buf[sdrHeaderSize:], nil
}

// Sensor Data Record
type SDR interface {
	// Returns record type
	Type() SDRType
	// Returns record id
	ID() uint16
	// Returns bytes of the record key and body
	Data() []byte
}

type sdrRaw struct {
	header *sdrHeader
	data   []byte
}

func (r *sdrRaw) Type() SDRType  { return r.header.RecordType }
func (r *sdrRaw) ID() uint16     { return r.header.RecordID }
func (r *sdrRaw) Data() []byte   { return r.data }
func (r *sdrRaw) String() string { return hex.EncodeToString(r.data) }

func (r *sdrRaw) Unmarshal(buf []byte) ([]byte, error) {
	r.data = buf
	return nil, nil
}

// Intersection of FullSensor and CompactSensor
type SDRCommonSensor struct {
	args   *Arguments
	header *sdrHeader
	data   []byte

	OwnerID       uint8
	OwnerLUN      uint8
	ChannelNumber uint8
	SensorNumber  uint8

	Entity struct {
		ID       uint8 // (See Table 43-13)
		Instance uint8
		Logical  bool
	}

	SensorInitialization struct {
		Scanning       bool
		EventGen       bool
		InitSensorType bool
		InitHysteresis bool
		InitThresholds bool
		InitEvents     bool
		InitScanning   bool
	}

	SensorCapabilities struct {
		EventMessage uint8
		Threshold    uint8
		Hysteresis   uint8
		AutoRearm    bool
		Ignore       bool
	}

	SensorType       SensorType
	EventReadingType uint8 // (See Table 42-1)

	Mask struct {
		AssertionOrLowerThreshold   uint16 // (See 15-16 byte in Table 43-1)
		DeassertionOrUpperThreshold uint16 // (See 17-18 byte in Table 43-1)
		DiscreteOrReadableThreshold uint16 // (See 19-20 byte in Table 43-1)
	}

	SensorUnits struct {
		Percentage   bool
		Modifier     uint8
		RateUnit     uint8
		Analog       uint8
		BaseType     UnitType
		ModifierType UnitType
	}
}

func (r *SDRCommonSensor) Type() SDRType { return r.header.RecordType }
func (r *SDRCommonSensor) ID() uint16    { return r.header.RecordID }
func (r *SDRCommonSensor) Data() []byte  { return r.data }

func (r *SDRCommonSensor) Unmarshal(buf []byte) ([]byte, error) {
	if l := len(buf); l < sdrCommonSensorSize {
		return nil, &MessageError{
			Message: fmt.Sprintf("Invalid SDRCommonSensor size : %d/%d", l, sdrCommonSensorSize),
			Detail:  hex.EncodeToString(buf),
		}
	}
	r.data = buf
	r.OwnerID = buf[0]
	r.OwnerLUN = buf[1] & 0x03
	r.ChannelNumber = buf[1] & 0xf0 >> 4
	r.SensorNumber = buf[2]
	r.Entity.ID = buf[3]
	r.Entity.Instance = buf[4] & 0x7f
	r.Entity.Logical = buf[4]&0x80 != 0
	r.SensorInitialization.Scanning = buf[5]&0x01 != 0
	r.SensorInitialization.EventGen = buf[5]&0x02 != 0
	r.SensorInitialization.InitSensorType = buf[5]&0x03 != 0
	r.SensorInitialization.InitHysteresis = buf[5]&0x04 != 0
	r.SensorInitialization.InitThresholds = buf[5]&0x05 != 0
	r.SensorInitialization.InitEvents = buf[5]&0x06 != 0
	r.SensorInitialization.InitScanning = buf[5]&0x07 != 0
	r.SensorCapabilities.EventMessage = buf[6] & 0x03
	r.SensorCapabilities.Threshold = buf[6] & 0x0c >> 2
	r.SensorCapabilities.Hysteresis = buf[6] & 0x30 >> 4
	r.SensorCapabilities.AutoRearm = buf[6]&0x40 != 0
	r.SensorCapabilities.Ignore = buf[6]&0x80 != 0
	r.SensorType = SensorType(buf[7])
	r.EventReadingType = buf[8]
	r.Mask.AssertionOrLowerThreshold = uint16(buf[9]) | uint16(buf[10])<<8
	r.Mask.DeassertionOrUpperThreshold = uint16(buf[11]) | uint16(buf[12])<<8
	r.Mask.DiscreteOrReadableThreshold = uint16(buf[13]) | uint16(buf[14])<<8
	r.SensorUnits.Percentage = buf[15]&0x01 != 0
	r.SensorUnits.Modifier = buf[15] & 0x06 >> 1
	r.SensorUnits.RateUnit = buf[15] & 0x38 >> 3
	r.SensorUnits.Analog = buf[15] & 0xc0 >> 6
	r.SensorUnits.BaseType = UnitType(buf[16])
	r.SensorUnits.ModifierType = UnitType(buf[17])

	return buf[sdrCommonSensorSize:], nil
}

// Full Sensor Record (Section 43.1)
type SDRFullSensor struct {
	SDRCommonSensor

	Linearization uint8
	M             int16
	Tolerance     uint8
	B             int16
	Accuracy      uint16
	AccuracyExp   uint8
	RExp          int8
	BExp          int8

	AnalogFlags struct {
		NominalRead bool
		NormalMax   bool
		NormalMin   bool
	}

	NominalRead uint8
	NormalMax   uint8
	NormalMin   uint8
	SensorMax   uint8
	SensorMin   uint8

	Threshold struct {
		UpperNonRecover    uint8
		UpperCrit          uint8
		UpperNonCrit       uint8
		LowerNonRecover    uint8
		LowerCrit          uint8
		LowerNonCrit       uint8
		PositiveHysteresis uint8
		NegativeHysteresis uint8
	}

	OEM      uint8
	IDType   uint8
	IDLength uint8
	IDString []byte
}

func (r *SDRFullSensor) Unmarshal(buf []byte) ([]byte, error) {
	if l := len(buf); l < sdrFullSensorSize {
		return nil, &MessageError{
			Message: fmt.Sprintf("Invalid SDRFullSensor size : %d/%d", l, sdrFullSensorSize),
			Detail:  hex.EncodeToString(buf),
		}
	}

	buf, err := r.SDRCommonSensor.Unmarshal(buf)
	if err != nil {
		return nil, err
	}

	r.Linearization = buf[0] & 0x7f
	r.M = tos16(uint16(buf[1])|uint16(buf[2]&0xc0)<<2, 10)
	r.Tolerance = buf[2] & 0x3f
	r.B = tos16(uint16(buf[3])|uint16(buf[4]&0xc0)<<2, 10)
	r.Accuracy = uint16(buf[4]&0x3f) | uint16(buf[5]&0xf0)<<2
	r.AccuracyExp = buf[5] & 0x0c
	r.RExp = int8(tos16(uint16(buf[6]&0xf0)>>4, 4))
	r.BExp = int8(tos16(uint16(buf[6]&0x0f), 4))
	r.AnalogFlags.NominalRead = buf[7]&0x01 != 0
	r.AnalogFlags.NormalMax = buf[7]&0x02 != 0
	r.AnalogFlags.NormalMin = buf[7]&0x04 != 0
	r.NominalRead = buf[8]
	r.NormalMax = buf[9]
	r.NormalMin = buf[10]
	r.SensorMax = buf[11]
	r.SensorMin = buf[12]
	r.Threshold.UpperNonRecover = buf[13]
	r.Threshold.UpperCrit = buf[14]
	r.Threshold.UpperNonCrit = buf[15]
	r.Threshold.LowerNonRecover = buf[16]
	r.Threshold.LowerCrit = buf[17]
	r.Threshold.LowerNonCrit = buf[18]
	r.Threshold.PositiveHysteresis = buf[19]
	r.Threshold.NegativeHysteresis = buf[20]
	r.OEM = buf[23]
	r.IDType = buf[24] & 0xc0 >> 6
	r.IDLength = buf[24] & 0x1f
	if l := int(r.IDLength); l > 0 {
		r.IDString = buf[25:]
		if l < len(r.IDString) {
			r.IDString = r.IDString[:l]
		}
	}

	return nil, nil
}

func (r *SDRFullSensor) SensorID() string {
	return decodeSensorID(r.IDType, r.IDString)
}

// Returns `true` if sensor is threshold-base.
func (r *SDRFullSensor) IsThresholdBaseSensor() bool {
	return r.EventReadingType == 0x01
}

// Returns `true` if sensor has an analog reading.
func (r *SDRFullSensor) IsAnalogReading() bool {
	// There is a discrete sensor that returns an analog reading.
	if r.args != nil && r.args.Discretereading {
		return r.SensorUnits.Analog < 0x03 && (r.IsThresholdBaseSensor() ||
			r.SensorUnits.Percentage || r.SensorUnits.Modifier != 0 ||
			r.SensorUnits.BaseType != 0 || r.SensorUnits.ModifierType != 0)
	}

	return r.SensorUnits.Analog < 0x03 && r.IsThresholdBaseSensor()
}

// Returns converted sensor reading.
func (r *SDRFullSensor) ConvertSensorReading(value uint8) float64 {
	var result float64

	// Conversion Formula (Section 36.3)
	switch r.SensorUnits.Analog {
	// unsigned
	case 0:
		result = (float64(int(r.M)*int(value)) + float64(r.B)*math.Pow10(int(r.BExp))) * math.Pow10(int(r.RExp))
	// 1's complement
	case 1:
		if value&0x80 != 0 {
			value += 1
		}
		fallthrough
	// 2's complement
	case 2:
		result = (float64(int(r.M)*int(int8(value))) + float64(r.B)*math.Pow10(int(r.BExp))) * math.Pow10(int(r.RExp))
	default:
		// Not analog sensor
		return 0.0
	}

	switch r.Linearization {
	case 0x01:
		return math.Log(result)
	case 0x02:
		return math.Log10(result)
	case 0x03:
		return math.Log2(result)
	case 0x04:
		return math.Exp(result)
	case 0x05:
		return math.Pow10(int(result))
	case 0x06:
		return math.Exp2(result)
	case 0x07:
		return math.Pow(result, -1.0)
	case 0x08:
		return math.Pow(result, 2.0)
	case 0x09:
		return math.Pow(result, 3.0)
	case 0x0a:
		return math.Sqrt(result)
	case 0x0b:
		return math.Cbrt(result)
	case 0x00:
		fallthrough
	default:
		return result
	}
}

func (r *SDRFullSensor) UnitString() string {
	var s string
	switch r.SensorUnits.Modifier {
	case 0x01:
		s = fmt.Sprintf("%s/%s", r.SensorUnits.BaseType, r.SensorUnits.ModifierType)
	case 0x02:
		s = fmt.Sprintf("%s * %s", r.SensorUnits.BaseType, r.SensorUnits.ModifierType)
	default:
		if r.SensorUnits.BaseType == 0 && r.SensorUnits.Percentage {
			return "percent"
		}
		s = r.SensorUnits.BaseType.String()
	}

	if r.SensorUnits.Percentage {
		s = "% " + s
	}
	return s
}

// FRU Device Locator Record (Section 43.8)
type SDRFRUDeviceLocator struct {
	header *sdrHeader
	data   []byte

	SlaveAddress       uint8
	DeviceID           uint8
	BusID              uint8
	AccessLUN          uint8
	Logical            bool
	ChannelNumber      uint8
	DeviceType         uint8
	DeviceTypeModifier uint8

	Entity struct {
		ID       uint8
		Instance uint8
	}

	OEM      uint8
	IDType   uint8
	IDLength uint8
	IDString []byte
}

func (r *SDRFRUDeviceLocator) Type() SDRType { return r.header.RecordType }
func (r *SDRFRUDeviceLocator) ID() uint16    { return r.header.RecordID }
func (r *SDRFRUDeviceLocator) Data() []byte  { return r.data }

func (r *SDRFRUDeviceLocator) Unmarshal(buf []byte) ([]byte, error) {
	if l := len(buf); l < sdrFRUDeviceLocatorSize {
		return nil, &MessageError{
			Message: fmt.Sprintf("Invalid SDRFRUDeviceLocator size : %d/%d", l, sdrFRUDeviceLocatorSize),
			Detail:  hex.EncodeToString(buf),
		}
	}
	r.data = buf
	r.SlaveAddress = buf[0] & 0xfe >> 1
	r.DeviceID = buf[1]
	r.BusID = buf[2] & 0x07
	r.AccessLUN = buf[2] & 18 >> 3
	r.Logical = buf[2]&0x80 != 0
	r.ChannelNumber = buf[3] & 0xf0 >> 4
	r.DeviceType = buf[5]
	r.DeviceTypeModifier = buf[6]
	r.Entity.ID = buf[7]
	r.Entity.Instance = buf[8]
	r.OEM = buf[9]
	r.IDType = buf[10] & 0xc0 >> 6
	r.IDLength = buf[10] & 0x1f
	if l := int(r.IDLength); l > 0 {
		r.IDString = buf[11:]
		if l < len(r.IDString) {
			r.IDString = r.IDString[:l]
		}
	}

	return nil, nil
}

func (r *SDRFRUDeviceLocator) SensorID() string {
	return decodeSensorID(r.IDType, r.IDString)
}

// Two's complement to signed int16
func tos16(n uint16, bits int) int16 {
	shift := uint(16 - bits)
	return int16(n<<shift) >> shift
}

func decodeSensorID(t uint8, b []byte) string {
	// Support only 8-bit ASCII (Section 43.15)
	switch t {
	case 0x03:
		return string(b)
	}
	return "0x" + hex.EncodeToString(b)
}

func sdrGetRecordHeaderAndNextID(c *Client, reservation, recordID uint16) (*sdrHeader, uint16, error) {
	gsc := &GetSDRCommand{
		ReservationID: reservation,
		RecordID:      recordID,
		RecordOffset:  0,
		ReadBytes:     sdrHeaderSize,
	}
	if err := c.Execute(gsc); err != nil {
		return nil, 0, err
	}

	header := &sdrHeader{}
	if _, err := header.Unmarshal(gsc.RecordData); err != nil {
		return nil, 0, err
	}
	if recordID != sdrFirstID && recordID != header.RecordID {
		header.RecordID = recordID
	}

	return header, gsc.NextRecordID, nil
}

func sdrGetRecord(c *Client, reservation uint16, header *sdrHeader) (SDR, error) {
	buf := make([]byte, header.RemainingBytes)

	for n := uint8(0); n < header.RemainingBytes; {
		r := header.RemainingBytes - n
		if r > c.sdrReadingBytes {
			r = c.sdrReadingBytes
		}

		gsc := &GetSDRCommand{
			ReservationID: reservation,
			RecordID:      header.RecordID,
			RecordOffset:  n + sdrHeaderSize,
			ReadBytes:     r,
		}
		if err := c.Execute(gsc); err != nil {
			// Adjust to the upper limit that BMC can be responded
			if e, ok := err.(*CommandError); ok && e.CompletionCode == CompletionRequestDataFieldExceedEd {
				if c.sdrReadingBytes > sdrHeaderSize {
					c.sdrReadingBytes -= 8
					if c.sdrReadingBytes < sdrHeaderSize {
						c.sdrReadingBytes = sdrHeaderSize
					}
					continue
				}
			}
			return nil, err
		}
		copy(buf[n:], gsc.RecordData)
		n += uint8(len(gsc.RecordData))
	}

	// TODO Add a new record type
	switch t := header.RecordType; t {
	case SDRTypeFullSensor:
		r := &SDRFullSensor{SDRCommonSensor: SDRCommonSensor{args: c.args, header: header}}
		if _, err := r.Unmarshal(buf); err != nil {
			return nil, err
		}
		return r, nil
	case SDRTypeFRUDeviceLocator:
		r := &SDRFRUDeviceLocator{header: header}
		if _, err := r.Unmarshal(buf); err != nil {
			return nil, err
		}
		return r, nil
	default:
		return &sdrRaw{
			header: header,
			data:   buf,
		}, nil
	}
}

// Returns all sensor records from SDR repository.
func SDRGetAllRecordsRepo(c *Client) ([]SDR, error) {
	return SDRGetRecordsRepo(c, nil)
}

// Returns sensor records from SDR repository.
func SDRGetRecordsRepo(c *Client, filter func(id uint16, t SDRType) bool) ([]SDR, error) {
	gic := &GetSDRRepositoryInfoCommand{}
	if err := c.Execute(gic); err != nil {
		return nil, err
	}

	if v := gic.SDRVersion; v != 0x01 && v != 0x51 && v != 0x02 {
		return nil, &MessageError{
			Message: fmt.Sprintf("Unknown SDR repository version : %d", v),
		}
	}
	if gic.RecordCount == 0 {
		return nil, &MessageError{
			Message: fmt.Sprintf("SDR record is zero in repository"),
		}
	}

	sensors := make([]SDR, 0, gic.RecordCount)

retry:
	rsc := &ReserveSDRRepositoryCommand{}
	if err := c.Execute(rsc); err != nil {
		return nil, err
	}
	reservation := rsc.ReservationID

	var header *sdrHeader
	var nextID uint16
	var err error

	for recordID := sdrFirstID; recordID != sdrLastID; {
		if header == nil {
			header, nextID, err = sdrGetRecordHeaderAndNextID(c, reservation, recordID)
			if err != nil {
				if e, ok := err.(*CommandError); ok && e.CompletionCode == CompletionReservationCancelled {
					goto retry
				}
				return nil, err
			}
		}

		if filter == nil || filter(header.RecordID, header.RecordType) {
			record, err := sdrGetRecord(c, reservation, header)
			if err != nil {
				if e, ok := err.(*CommandError); ok && e.CompletionCode == CompletionReservationCancelled {
					goto retry
				}
				return nil, err
			}

			sensors = append(sensors, record)
		}

		header = nil
		recordID = nextID
	}

	return sensors, nil
}
