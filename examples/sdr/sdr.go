package main

import (
	"fmt"
	"time"

	"github.com/k-sone/ipmigo"
)

// | Name | Type | Reading | Units | Status(for threshold-base) |
var format string = "| %-16s | %-30s | %-10s | %-20s | %-3s |\n"

// Print sensor data repository entries and readings.
func main() {
	c, err := ipmigo.NewClient(ipmigo.Arguments{
		Version:       ipmigo.V2_0,
		Address:       "192.168.1.1:623",
		Timeout:       2 * time.Second,
		Retries:       1,
		Username:      "myuser",
		Password:      "mypass",
		CipherSuiteID: 3,
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	if err := c.Open(); err != nil {
		fmt.Println(err)
		return
	}
	defer c.Close()

	// Get sensor records
	records, err := ipmigo.SDRGetRecordsRepo(c, func(id uint16, t ipmigo.SDRType) bool {
		return t == ipmigo.SDRTypeFullSensor || t == ipmigo.SDRTypeCompactSensor
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, r := range records {
		// Get sensor reading
		var run, num uint8
		switch s := r.(type) {
		case *ipmigo.SDRFullSensor:
			run = s.OwnerLUN
			num = s.SensorNumber
		case *ipmigo.SDRCompactSensor:
			run = s.OwnerLUN
			num = s.SensorNumber
		}
		gsr := &ipmigo.GetSensorReadingCommand{
			RsLUN:        run,
			SensorNumber: num,
		}
		err, ok := c.Execute(gsr).(*ipmigo.CommandError)
		if err != nil && !ok {
			fmt.Println(err)
			return
		}

		// Output sensor reading
		var convf func(uint8) float64
		var analog, threshold bool
		var sname, stype string
		units, reading, status := "discrete", "n/a", "n/a"

		switch s := r.(type) {
		case *ipmigo.SDRFullSensor:
			convf = func(r uint8) float64 { return s.ConvertSensorReading(r) }
			analog = s.IsAnalogReading()
			threshold = s.IsThresholdBaseSensor()
			sname = s.SensorID()
			stype = s.SensorType.String()
			if analog {
				units = s.UnitString()
			}
		case *ipmigo.SDRCompactSensor:
			analog = false
			threshold = false
			sname = s.SensorID()
			stype = s.SensorType.String()
		}

		if err != nil {
			status = err.CompletionCode.String()
		} else {
			if gsr.IsValid() {
				if analog {
					if threshold {
						status = string(gsr.ThresholdStatus())
					}
					reading = fmt.Sprintf("%.2f", convf(gsr.SensorReading))
				} else {
					reading = fmt.Sprintf("0x%02x", gsr.SensorReading)
				}
			}
		}
		fmt.Printf(format, sname, stype, reading, units, status)
	}
}
