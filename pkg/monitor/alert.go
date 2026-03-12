package monitor

import (
	"errors"
	"fmt"
)

type AlertType int

const (
	AlertOther AlertType = iota
	AlertWarning
	// Indicates log is misbehaving, or not responding.
	AlertLogError
	AlertInvalidLogSignature
	AlertInconsistentTreeHead
)

func (t AlertType) String() string {
	switch t {
	case AlertOther:
		return "Other"
	case AlertWarning:
		return "Warning"
	case AlertLogError:
		return "Log not responding as expected"
	case AlertInvalidLogSignature:
		return "Invalid log signature"
	case AlertInconsistentTreeHead:
		return "Log tree head not consistent"
	default:
		return fmt.Sprintf("Unknown alert type %d", t)
	}
}

type Alert struct {
	Type AlertType
	Err  error
}

func (a *Alert) Error() string {
	return fmt.Sprintf("monitoring alert: %s: %s", a.Type, a.Err)
}

func (a *Alert) Unwrap() error {
	return a.Err
}

func newAlert(t AlertType, msg string, args ...interface{}) *Alert {
	return &Alert{Type: t, Err: fmt.Errorf(msg, args...)}
}

func ErrorAlertType(e error) AlertType {
	var a *Alert
	if errors.As(e, &a) {
		return a.Type
	}
	return AlertOther
}
