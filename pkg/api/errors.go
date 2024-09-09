package api

import (
	"errors"
	"fmt"
	"net/http"
)

// Partial success from AddLeaf, caller should retry.
var ErrAccepted *Error = NewError(http.StatusAccepted, fmt.Errorf("Accepted")) // 202

// E.g., out of range request parameters.
var ErrBadRequest *Error = NewError(http.StatusBadRequest, fmt.Errorf("Bad Request")) // 400

// Unauthorized, typically because signature is invalid, or public key
// not recognized.
var ErrForbidden *Error = NewError(http.StatusForbidden, fmt.Errorf("Forbidden")) // 403

// E.g., GetInclusionProof fails because leaf isn't included.
var ErrNotFound *Error = NewError(http.StatusNotFound, fmt.Errorf("Not Found")) // 404

// Failure of witness AddTreeHead, caller should retry with correct
// tree size.
var ErrConflict *Error = NewError(http.StatusConflict, fmt.Errorf("Conflict")) // 409

// Failure of witness AddTreeHead, invalid consistency proof.
var ErrUnprocessableEntity *Error = NewError(422, fmt.Errorf("Unprocessable Entity"))

// Error due to exceeded rate limit.
var ErrTooManyRequests *Error = NewError(http.StatusTooManyRequests, fmt.Errorf("Too Many Requests")) // 429

// An error with an associated HTTP status code.
type Error struct {
	statusCode int // HTTP status code for this error
	err        error
}

func (e *Error) StatusCode() int {
	return e.statusCode
}

func (e *Error) Error() string {
	return fmt.Sprintf("(%d) %s", e.statusCode, e.err)
}

func (e *Error) Unwrap() error {
	return e.err
}

// Return a new error, with same status code, but the supplied
// underlying error.
func (e *Error) WithError(err error) *Error {
	return &Error{statusCode: e.statusCode, err: err}
}

type errorWithOldSize struct {
	oldSize uint64
}

func (e *errorWithOldSize) Error() string {
	return fmt.Sprintf("old size must be %d", e.oldSize)
}

func (e *Error) WithOldSize(oldSize uint64) *Error {
	if e.statusCode != http.StatusConflict {
		panic("only Conflict (409) errors can have an associated old size")
	}
	return e.WithError(&errorWithOldSize{oldSize})
}

// An error is considered matching if the status code is the same.
// Example usage:
//
//	if errors.Is(api.ErrNotFound, err) {...}
func (e *Error) Is(err error) bool {
	if err, ok := err.(*Error); ok {
		return e.statusCode == err.statusCode
	}
	return false
}

func NewError(statusCode int, err error) *Error {
	// TODO: Allow err == nil, and return nil for that case?
	if statusCode == http.StatusOK || err == nil {
		panic(fmt.Sprintf("Invalid call to NewError, status = %d, err = %v",
			statusCode, err))
	}
	if statusCode == 0 {
		return &Error{
			statusCode: http.StatusInternalServerError,
			err:        fmt.Errorf("invalid status code 0 for error: %s", err),
		}
	}
	return &Error{statusCode: statusCode, err: err}
}

func ErrorStatusCode(err error) int {
	var apiError *Error
	if errors.As(err, &apiError) {
		return apiError.StatusCode()
	}
	return http.StatusInternalServerError
}

// An error associated with an old size must be a Conflict error with
// the wrapped error being an errorWithOldSize.
func ErrorConflictOldSize(err error) (uint64, bool) {
	var apiError *Error
	if errors.As(err, &apiError) && apiError.statusCode == http.StatusConflict {
		var oldSizeError *errorWithOldSize
		if errors.As(apiError.err, &oldSizeError) {
			return oldSizeError.oldSize, true
		}
	}
	return 0, false
}
