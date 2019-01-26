package ipmigo

import (
	"fmt"
)

// An ArgumentError suggests that the arguments are wrong
type ArgumentError struct {
	Value   interface{} // Argument that has a problem
	Message string      // Error message
}

func (e *ArgumentError) Error() string {
	return fmt.Sprintf("%s, value `%v`", e.Message, e.Value)
}

// A MessageError suggests that the received message is wrong or is not obtained
type MessageError struct {
	Cause   error  // Cause of the error
	Message string // Error message
	Detail  string // Detail of the error for debugging
}

func (e *MessageError) Error() string {
	if e.Cause == nil {
		return e.Message
	} else {
		return fmt.Sprintf("%s, cause `%v`", e.Message, e.Cause)
	}
}

var ErrNotSupportedIPMI error = &MessageError{Message: "Not Supported IPMI"}

// A CommandError suggests that command execution has failed
type CommandError struct {
	CompletionCode CompletionCode
	Command        Command
}

func (e *CommandError) Error() string {
	return fmt.Sprintf("Command %s(%02x) failed - %s", e.Command.Name(), e.Command.Code(), e.CompletionCode)
}
