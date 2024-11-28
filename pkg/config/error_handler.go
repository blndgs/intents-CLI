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

func (e *CustomError) Error() string {
	var builder strings.Builder

	// Error header with file and line information
	red := color.New(color.FgRed, color.Bold)
	builder.WriteString(red.Sprintf("Error occurred in %s:%d\n", e.File, e.Line))
	builder.WriteString(red.Sprint("Function: " + e.Function + "\n"))

	// Error message and details
	builder.WriteString(fmt.Sprintf("Details: %s\n", e.Msg))
	if e.Err != nil {
		builder.WriteString(fmt.Sprintf("Underlying error: %v\n", e.Err))
	}

	return builder.String()
}

// NewError creates a CustomError with stack information
func NewError(msg string, err error) *CustomError {
	pc, file, line, _ := runtime.Caller(1)
	fn := runtime.FuncForPC(pc)

	return &CustomError{
		Msg:      msg,
		Err:      err,
		File:     file,
		Line:     line,
		Function: fn.Name(),
	}
}
