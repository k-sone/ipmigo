package ipmigo

import (
	"fmt"
)

type ThresholdStatus string

const (
	// Normal operating ranges
	ThresholdStatusOK ThresholdStatus = "ok"
	// Lower Non-Recoverable
	ThresholdStatusLNR ThresholdStatus = "lnr"
	// Lower Critical
	ThresholdStatusLCR ThresholdStatus = "lcr"
	// Lower Non-Critical
	ThresholdStatusLNC ThresholdStatus = "lnc"
	// Upper Non-Recoverable
	ThresholdStatusUNR ThresholdStatus = "unr"
	// Upper Critical
	ThresholdStatusUCR ThresholdStatus = "ucr"
	// Upper Non-Critical
	ThresholdStatusUNC ThresholdStatus = "unc"
)

// Returns threshold status of threshold-base sensor.
func NewThresholdStatus(status uint8) ThresholdStatus {
	if status&0x04 != 0 {
		return ThresholdStatusLNR
	} else if status&0x20 != 0 {
		return ThresholdStatusUNR
	} else if status&0x02 != 0 {
		return ThresholdStatusLCR
	} else if status&0x10 != 0 {
		return ThresholdStatusUCR
	} else if status&0x01 != 0 {
		return ThresholdStatusLNC
	} else if status&0x08 != 0 {
		return ThresholdStatusUNC
	} else {
		return ThresholdStatusOK
	}
}

// Sensor Type (Table 42-3)
type SensorType uint8

var sensorTypeDescriptions []string = []string{
	"reserved",
	"Temperature",
	"Voltage",
	"Current",
	"Fan",
	"Physical Security",
	"Platform Security",
	"Processor",
	"Power Supply",
	"Power Unit",
	"Cooling Device",
	"Other Units-based Sensor",
	"Memory",
	"Drive Slot",
	"POST Memory Resize",
	"System Firmware",
	"Event Logging Disabled",
	"Watchdog 1",
	"System Event",
	"Critical Interrupt",
	"Button / Switch",
	"Module / Board",
	"Microcontroller",
	"Add-in Card",
	"Chassis",
	"Chip Set",
	"Other FRU",
	"Cable / Interconnect",
	"Terminator",
	"System Boot Initiated",
	"Boot Error",
	"OS Boot",
	"OS Stop",
	"Slot / Connector",
	"System ACPI Power State",
	"Watchdog 2",
	"Platform Alert",
	"Entity Presence",
	"Monitor ASIC",
	"LAN",
	"Management Subsystem Health",
	"Battery",
	"Session Audit",
	"Version Change",
	"FRU State",
}

func (t SensorType) String() string {
	if i := int(t); i < len(sensorTypeDescriptions) {
		return sensorTypeDescriptions[i]
	} else if i < 0xc0 {
		return fmt.Sprintf("Reserved(%d)", i)
	} else {
		return fmt.Sprintf("OEM RESERVED(%d)", i)
	}
}

// Sensor Unit Type (Section 43.17)
type UnitType uint8

var unitDescriptions []string = []string{
	"unspecified",
	"degrees C",
	"degrees F",
	"degrees K",
	"Volts",
	"Amps",
	"Watts",
	"Joules",
	"Coulombs",
	"VA",
	"Nits",
	"lumen",
	"lux",
	"Candela",
	"kPa",
	"PSI",
	"Newton",
	"CFM",
	"RPM",
	"Hz",
	"microsecond",
	"millisecond",
	"second",
	"minute",
	"hour",
	"day",
	"week",
	"mil",
	"inches",
	"feet",
	"cu in",
	"cu feet",
	"mm",
	"cm",
	"m",
	"cu cm",
	"cu m",
	"liters",
	"fluid ounce",
	"radians",
	"steradians",
	"revolutions",
	"cycles",
	"gravities",
	"ounce",
	"pound",
	"ft-lb",
	"oz-in",
	"gauss",
	"gilberts",
	"henry",
	"millihenry",
	"farad",
	"microfarad",
	"ohms",
	"siemens",
	"mole",
	"becquerel",
	"PPM",
	"reserved",
	"Decibels",
	"DbA",
	"DbC",
	"gray",
	"sievert",
	"color temp deg K",
	"bit",
	"kilobit",
	"megabit",
	"gigabit",
	"byte",
	"kilobyte",
	"megabyte",
	"gigabyte",
	"word",
	"dword",
	"qword",
	"line",
	"hit",
	"miss",
	"retry",
	"reset",
	"overflow",
	"underrun",
	"collision",
	"packets",
	"messages",
	"characters",
	"error",
	"correctable error",
	"uncorrectable error",
}

func (u UnitType) String() string {
	if i := int(u); i < len(unitDescriptions) {
		return unitDescriptions[i]
	}
	return fmt.Sprint("unknown(%d)", u)
}
