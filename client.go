package ipmigo

import (
	"fmt"
	"time"
)

type Version int

const (
	V1_5 Version = iota + 1
	V2_0
)

// Channel Privilege Levels. (Section 6.8)
type PrivilegeLevel uint8

const (
	PrivilegeCallback PrivilegeLevel = iota + 1
	PrivilegeUser
	PrivilegeOperator
	PrivilegeAdministrator
)

func (p PrivilegeLevel) String() string {
	switch p {
	case PrivilegeCallback:
		return "CALLBACK"
	case PrivilegeUser:
		return "USER"
	case PrivilegeOperator:
		return "OPERATOR"
	case PrivilegeAdministrator:
		return "ADMINISTRATOR"
	default:
		return fmt.Sprintf("Unknown(%d)", p)
	}
}

// An argument for creating an IPMI Client
type Arguments struct {
	Version        Version        // IPMI version to use
	Network        string         // See net.Dial parameter (The default is `udp`)
	Address        string         // See net.Dial parameter
	Timeout        time.Duration  // Each connect/read-write timeout (The default is 5sec)
	Retries        uint           // Number of retries (The default is `0`)
	Username       string         // Remote server username
	Password       string         // Remote server password
	PrivilegeLevel PrivilegeLevel // Session privilege level (The default is `Administrator`)
	CipherSuiteID  uint           // ID of cipher suite, See Table 22-20 (The default is `0` which no auth and no encrypt)
}

func (a *Arguments) setDefault() {
	if a.Version == 0 {
		a.Version = V2_0
	}
	if a.Network == "" {
		a.Network = "udp"
	}
	if a.Timeout == 0 {
		a.Timeout = 5 * time.Second
	}
	if a.PrivilegeLevel == 0 {
		a.PrivilegeLevel = PrivilegeAdministrator
	}
}

func (a *Arguments) validate() error {
	switch a.Version {
	case V2_0:
		if len(a.Password) > passwordMaxLengthV2_0 {
			return &ArgumentError{
				Value:   a.Password,
				Message: "Password is too long",
			}
		}
		if a.CipherSuiteID < 0 || a.CipherSuiteID > uint(len(cipherSuiteIDs)-1) {
			return &ArgumentError{
				Value:   a.CipherSuiteID,
				Message: "Invalid Cipher Suite ID",
			}
		}
		if a.CipherSuiteID > 3 {
			return &ArgumentError{
				Value:   a.CipherSuiteID,
				Message: "Unsupported Cipher Suite ID in ipmigo",
			}
		}
	case V1_5:
		// TODO Support v1.5 ?
		fallthrough
	default:
		return &ArgumentError{
			Value:   a.Version,
			Message: "Unsupported IPMI version",
		}
	}

	if a.PrivilegeLevel < 0 || a.PrivilegeLevel > PrivilegeAdministrator {
		return &ArgumentError{
			Value:   a.PrivilegeLevel,
			Message: "Invalid Privilege Level",
		}
	}

	if len(a.Username) > userNameMaxLength {
		return &ArgumentError{
			Value:   a.Username,
			Message: "Username is too long",
		}
	}

	return nil
}

// IPMI Client
type Client struct {
	session session
}

func (c *Client) Ping() error               { return c.session.Ping() }
func (c *Client) Open() error               { return c.session.Open() }
func (c *Client) Close() error              { return c.session.Close() }
func (c *Client) Execute(cmd Command) error { return c.session.Execute(cmd) }

// Create an IPMI Client
func NewClient(args Arguments) (*Client, error) {
	if err := args.validate(); err != nil {
		return nil, err
	}
	args.setDefault()

	var s session
	switch args.Version {
	case V1_5:
		s = newSessionV1_5(&args)
	case V2_0:
		s = newSessionV2_0(&args)
	}
	return &Client{session: s}, nil
}
