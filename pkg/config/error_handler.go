package config

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/fatih/color"
)

// CustomError wraps errors with additional context
type CustomError struct {
	Msg      string
	Err      error
	File     string
	Line     int
	Function string
}

const maxErrorLength = 1000

func formatErrorHeader(file string, line int, function string) string {
	red := color.New(color.FgRed, color.Bold)
	return red.Sprintf("Error occurred in %s:%d\nFunction: %s\n", file, line, function)
}

func (e *CustomError) Error() string {
	var builder strings.Builder
	builder.WriteString(formatErrorHeader(e.File, e.Line, e.Function))

	// Truncate message if too long
	msg := e.Msg
	if len(msg) > maxErrorLength {
		msg = msg[:maxErrorLength] + "..."
	}
	builder.WriteString(fmt.Sprintf("Details: %s\n", msg))

	if e.Err != nil {
		errMsg := e.Err.Error()
		if len(errMsg) > maxErrorLength {
			errMsg = errMsg[:maxErrorLength] + "..."
		}
		builder.WriteString(fmt.Sprintf("Underlying error: %v\n", errMsg))
	}

	return builder.String()
}

// NewError creates a CustomError with stack information.
// It captures the caller's context by skipping one stack frame (the immediate caller).
func NewError(msg string, err error) *CustomError {
	// Validate the message input
	if msg == "" {
		msg = "unknown error"
	}

	// Retrieve caller information
	pc, file, line, ok := runtime.Caller(1) // Skip one level to get the caller's info
	if !ok {
		// If runtime.Caller fails, return a CustomError with unknown location
		return &CustomError{
			Msg:      msg,
			Err:      err,
			File:     "unknown",
			Line:     0,
			Function: "unknown",
		}
	}

	// Get function details from program counter
	fn := runtime.FuncForPC(pc)
	functionName := "unknown"
	if fn != nil {
		functionName = fn.Name()
	}

	return &CustomError{
		Msg:      msg,
		Err:      err,
		File:     file,
		Line:     line,
		Function: functionName,
	}
}
