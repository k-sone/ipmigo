package ipmigo

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

const (
	selFirstID uint16 = 0x0000
	selLastID  uint16 = 0xffff

	selRecordSize = 16
)

// Sensor Event Log Record Type
type SELType uint8

func (t SELType) IsTimestampedOEM() bool    { return t >= 0xc0 && t <= 0xdf }
func (t SELType) IsNonTimestampedOEM() bool { return t >= 0xe0 && t <= 0xff }

// Sensor Event Log Record
type SELRecord interface {
	// Returns record type
	Type() SELType
	// Returns record id
	ID() uint16
	// Returns bytes of the record key and body
	Data() []byte
}

// SEL Event Record (Section 32.1)
type SELEventRecord struct {
	data []byte

	RecordID     uint16
	RecordType   SELType
	Timestamp    Timestamp
	GeneratorID  uint16
	EvMRev       uint8
	SensorType   SensorType
	SensorNumber uint8
	EventType    EventType
	EventDir     uint8
	EventData1   uint8 // (Table 29-6)
	EventData2   uint8 // (Table 29-6)
	EventData3   uint8 // (Table 29-6)
}

func (r *SELEventRecord) Type() SELType { return r.RecordType }
func (r *SELEventRecord) ID() uint16    { return r.RecordID }
func (r *SELEventRecord) Data() []byte  { return r.data }

func (r *SELEventRecord) Unmarshal(buf []byte) ([]byte, error) {
	if l := len(buf); l < selRecordSize {
		return nil, &MessageError{
			Message: fmt.Sprintf("Invalid SELEventRecord size : %d/%d", l, selRecordSize),
			Detail:  hex.EncodeToString(buf),
		}
	}
	r.data = buf[:selRecordSize]
	r.RecordID = binary.LittleEndian.Uint16(buf[0:2])
	r.RecordType = SELType(buf[2])
	r.Timestamp.Value = binary.LittleEndian.Uint32(buf[3:7])
	r.GeneratorID = binary.LittleEndian.Uint16(buf[7:9])
	r.EvMRev = buf[9]
	r.SensorType = SensorType(buf[10])
	r.SensorNumber = buf[11]
	r.EventType = EventType(buf[12] & 0x7f)
	r.EventDir = buf[12] & 0x80 >> 7
	r.EventData1 = buf[13]
	r.EventData2 = buf[14]
	r.EventData3 = buf[15]

	return buf[selRecordSize:], nil
}

// Returns `true'` if it is assertion event.
func (r *SELEventRecord) IsAssertionEvent() bool { return r.EventDir == 0 }

// Returns trigger reading of threshold-base sensor.
func (r *SELEventRecord) GetEventTriggerReading() (uint8, bool) {
	if r.EventType.IsThreshold() && r.EventData1&0xc0 == 0x40 && r.EventData2 != 0xff {
		return r.EventData2, true
	}
	return 0, false
}

// Returns trigger threshold value of threshold-base sensor.
func (r *SELEventRecord) GetEventTriggerThreshold() (uint8, bool) {
	if r.EventType.IsThreshold() && r.EventData1&0x30 == 0x10 && r.EventData3 != 0xff {
		return r.EventData3, true
	}
	return 0, false
}

// Returns event description.
func (r *SELEventRecord) Description() string {
	var f func() (string, bool)
	switch t := r.EventType; {
	case t.IsGeneric() || t.IsThreshold():
		f = func() (string, bool) {
			offset := r.EventData1 & 0x0f
			desc, ok := sensorGenericEventDesc[uint32(r.EventType)<<8|uint32(offset)]
			return desc, ok
		}
	case t.IsSensorSpecific():
		f = func() (string, bool) {
			d2 := uint8(0xff)
			if r.EventData1&0xc0 != 0 {
				d2 = r.EventData2
			}
			d3 := uint8(0xff)
			if r.EventData1&0x30 != 0 {
				d3 = r.EventData3
			}

			offset := r.EventData1 & 0x0f
			for {
				// First, try to get a more detailed definition
				desc, ok := sensorSpecificEventDesc[uint32(r.SensorType)<<24|uint32(offset)<<16|uint32(d2)<<8|uint32(d3)]
				if !ok && (d2 != 0xff || d3 != 0xff) {
					// If not found, get a general definition
					d2, d3 = 0xff, 0xff
					continue
				}
				return desc, ok
			}
		}
	case t.IsOEM():
		f = func() (string, bool) {
			return fmt.Sprintf("OEM Event: Type=0x%02x, Data1=0x%02x, Data2=0x%02x, Data3=0x%02x",
				r.EventType, r.EventData1, r.EventData2, r.EventData3), true
		}
	default:
		f = func() (string, bool) { return "", false }
	}

	if desc, ok := f(); ok {
		return desc
	} else {
		return fmt.Sprintf("Event: Type=0x%02x, Data1=0x%02x, Data2=0x%02x, Data3=0x%02x",
			r.EventType, r.EventData1, r.EventData2, r.EventData3)
	}
}

// Timestamped OEM SEL record (Section 32.2)
type SELTimestampedOEMRecord struct {
	data []byte

	RecordID       uint16
	RecordType     SELType
	Timestamp      Timestamp
	ManufacturerID uint32
	OEMDefined     []byte
}

func (r *SELTimestampedOEMRecord) Type() SELType { return r.RecordType }
func (r *SELTimestampedOEMRecord) ID() uint16    { return r.RecordID }
func (r *SELTimestampedOEMRecord) Data() []byte  { return r.data }

func (r *SELTimestampedOEMRecord) Unmarshal(buf []byte) ([]byte, error) {
	if l := len(buf); l < selRecordSize {
		return nil, &MessageError{
			Message: fmt.Sprintf("Invalid SELTimestampedOEMRecord size : %d/%d", l, selRecordSize),
			Detail:  hex.EncodeToString(buf),
		}
	}
	r.data = buf[:selRecordSize]
	r.RecordID = binary.LittleEndian.Uint16(buf[0:2])
	r.RecordType = SELType(buf[2])
	r.Timestamp.Value = binary.LittleEndian.Uint32(buf[3:7])
	r.ManufacturerID = uint32(buf[7]) | uint32(buf[8])<<8 | uint32(buf[9])<<16
	r.OEMDefined = buf[10:selRecordSize]

	return buf[selRecordSize:], nil
}

// Non-Timestamped OEM SEL record (Section 32.3)
type SELNonTimestampedOEMRecord struct {
	data []byte

	RecordID   uint16
	RecordType SELType
	OEM        []byte
}

func (r *SELNonTimestampedOEMRecord) Type() SELType { return r.RecordType }
func (r *SELNonTimestampedOEMRecord) ID() uint16    { return r.RecordID }
func (r *SELNonTimestampedOEMRecord) Data() []byte  { return r.data }

func (r *SELNonTimestampedOEMRecord) Unmarshal(buf []byte) ([]byte, error) {
	if l := len(buf); l < selRecordSize {
		return nil, &MessageError{
			Message: fmt.Sprintf("Invalid SELNonTimestampedOEMRecord size : %d/%d", l, selRecordSize),
			Detail:  hex.EncodeToString(buf),
		}
	}
	r.data = buf[:selRecordSize]
	r.RecordID = binary.LittleEndian.Uint16(buf[0:2])
	r.RecordType = SELType(buf[2])
	r.OEM = buf[3:selRecordSize]

	return buf[selRecordSize:], nil
}

func selGetRecord(c *Client, reservation, id uint16) (record SELRecord, nextID uint16, err error) {
	nextID = selLastID

	gse := &GetSELEntryCommand{
		ReservationID: reservation,
		RecordID:      id,
		RecordOffset:  0x00,
		ReadBytes:     0xff,
	}
	if err = c.Execute(gse); err != nil {
		return
	}
	if l := len(gse.RecordData); l < 3 {
		err = &MessageError{Message: fmt.Sprintf("Invalid SELRecord size : %d", l)}
		return
	}

	if t := SELType(gse.RecordData[2]); t.IsTimestampedOEM() {
		r := &SELTimestampedOEMRecord{}
		if _, err = r.Unmarshal(gse.RecordData); err != nil {
			return
		}
		record = r
	} else if t.IsNonTimestampedOEM() {
		r := &SELNonTimestampedOEMRecord{}
		if _, err = r.Unmarshal(gse.RecordData); err != nil {
			return
		}
		record = r
	} else {
		r := &SELEventRecord{}
		if _, err = r.Unmarshal(gse.RecordData); err != nil {
			return
		}
		record = r
	}

	return record, gse.NextRecordID, nil
}

func SELGetEntries(c *Client, offset, num int) (records []SELRecord, total int, err error) {
	gsi := &GetSELInfoCommand{}
	if err = c.Execute(gsi); err != nil {
		return
	}

	if v := gsi.SELVersion; v != 0x51 && v != 0x02 {
		return nil, 0, &MessageError{
			Message: fmt.Sprintf("Unknown SEL version : %d", v),
		}
	}
	total = int(gsi.Entries)

	if total == 0 || num <= 0 || offset < 0 || offset >= total {
		return
	}
	if n := total - offset; num > n {
		num = n
	}

	roffset := selFirstID
	if offset > 0 {
		// get first record
		r, n, e := selGetRecord(c, 0x00, selFirstID)
		if e != nil {
			return
		}

		delta := n - r.ID()
		roffset = delta*uint16(offset) + r.ID()
	}

	records = make([]SELRecord, 0, num)

	rsc := &ReserveSELCommand{}
	if err = c.Execute(rsc); err != nil {
		return
	}

	for n, id := 0, roffset; n < num && id != selLastID; n++ {
		var r SELRecord
		if r, id, err = selGetRecord(c, rsc.ReservationID, id); err != nil {
			return
		}
		records = append(records, r)
	}

	if l := len(records); l > num {
		records = records[l-num:]
	}
	return
}
