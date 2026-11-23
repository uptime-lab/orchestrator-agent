// Package refusal marks a command the agent declined to execute — a parameter
// it will not act on, a command type it does not know, a path or unit its
// policy forbids — as distinct from a command that ran and failed. The command
// is reported failed either way; the difference is how the device logs it: a
// refusal is the caller's input being turned away, which is expected and
// answered, not a fault on the device.
//
// Pure and dependency-free so that the command handlers (which decide) and the
// gRPC client (which logs) share one definition.
package refusal

import "errors"

// Error wraps the reason a command was refused. Its text is the reason's text.
type Error struct{ Err error }

func (e *Error) Error() string { return e.Err.Error() }

func (e *Error) Unwrap() error { return e.Err }

// Wrap marks err as a refusal. nil stays nil, and an error already marked is
// returned unchanged.
func Wrap(err error) error {
	if err == nil || Is(err) {
		return err
	}
	return &Error{Err: err}
}

// Is reports whether err, or any error it wraps, is a refusal.
func Is(err error) bool {
	var r *Error
	return errors.As(err, &r)
}
