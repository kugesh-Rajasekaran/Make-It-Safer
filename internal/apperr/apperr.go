// Package apperr defines the error type used across Make-It-Safer.
//
// Every error shown to a user carries a stable, area-prefixed code (for
// example VAULT_UNLOCK_FAILED). Codes appear in human output and in the
// --json envelope, so scripts and agents can react to them. Messages must
// never contain secrets.
package apperr

import "errors"

// Error is an error with a stable code and a message that is safe to show.
type Error struct {
	Code    string // area-prefixed code, e.g. SERVER_HOSTKEY_MISMATCH
	Message string // what happened and, where useful, how to fix it
	Err     error  // optional underlying cause
}

func (e *Error) Error() string {
	if e.Err == nil {
		return e.Message
	}
	return e.Message + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

// New returns an error with a code and a message.
func New(code, message string) *Error {
	return &Error{Code: code, Message: message}
}

// Wrap returns an error with a code and a message that wraps err.
func Wrap(code string, err error, message string) *Error {
	return &Error{Code: code, Message: message, Err: err}
}

// CodeOf returns the code of the first *Error in err's chain, or
// CLIUnexpected when err carries no code.
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return CLIUnexpected
}

// Is reports whether err carries the given code.
func Is(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}
