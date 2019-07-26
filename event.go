package ipmigo

// Event/Reading Type (Table 42-2)
type EventType uint8

func (e EventType) IsUnspecified() bool    { return e == 0x00 }
func (e EventType) IsThreshold() bool      { return e == 0x01 }
func (e EventType) IsGeneric() bool        { return e >= 0x02 && e <= 0x0c }
func (e EventType) IsSensorSpecific() bool { return e == 0x6f }
func (e EventType) IsOEM() bool            { return e >= 0x70 && e <= 0x7f }
