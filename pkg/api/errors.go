package api

import (
	"errors"
	"fmt"
	"net/http"
)

// Partial success from AddLeaf, caller should retry.
var ErrAccepted error = NewError(http.StatusAccepted, fmt.Errorf("Accepted")) // 202

// E.g., GetInclusionProof fails because leaf isn't included.
var ErrNotFound error = NewError(http.StatusNotFound, fmt.Errorf("Not Found")) // 404

// Failure of witness AddTreeHead, caller should retry with correct
// tree size.
var ErrConflict error = NewError(http.StatusConflict, fmt.Errorf("Conflict"))

// Failure of witness AddTreeHead, invalid consistency proof.
var ErrUnprocessableEntity error = NewError(422, fmt.Errorf("Unprocessable Entity"))

// Unauthorized, typically because signature is invalid, or public key
// not recognized.
var ErrForbidden error = NewError(http.StatusForbidden, fmt.Errorf("Forbidden")) // 403

// Error due to exceeded rate limit.
var ErrTooManyRequests error = NewError(http.StatusTooManyRequests, fmt.Errorf("Too Many Requests")) // 429

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
	if statusCode == 0 || statusCode == http.StatusOK || err == nil {
		panic(fmt.Sprintf("Invalid call to NewError, status = %d, err = %v",
			statusCode, err))
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
