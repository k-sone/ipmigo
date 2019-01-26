package ipmigo

import (
	"encoding/json"
	"net"
)

func toJSON(s interface{}) string {
	r, _ := json.Marshal(s)
	return string(r)
}

func retry(retries int, f func() error) (err error) {
	for i := 0; i <= retries; i++ {
		err = f()
		switch e := err.(type) {
		case net.Error:
			if e.Timeout() {
				continue
			}
		}
		return
	}
	return
}
