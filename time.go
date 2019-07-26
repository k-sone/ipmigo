package ipmigo

import (
	"time"
)

const (
	timestampUnspecified = 0xffffffff
	timestampPostInitMin = 0x00000000
	timestampPostInitMax = 0x20000000
)

// Timestamp (Section 37)
type Timestamp struct {
	Value uint32
}

func (t *Timestamp) IsUnspecified() bool {
	return t.Value == timestampUnspecified
}

func (t *Timestamp) IsPostInit() bool {
	return t.Value >= timestampPostInitMin && t.Value <= timestampPostInitMax
}

func (t *Timestamp) Format(format string) string {
	if t.IsUnspecified() {
		return "Unspecified"
	}
	if t.IsPostInit() {
		return "Post-Init"
	}
	return time.Unix(int64(t.Value), 0).Format(format)
}

func (t *Timestamp) String() string {
	return t.Format(time.RFC3339)
}
