package offline

import "fmt"

type InvalidRequestError struct {
	message string
	err     error
}

func (e *InvalidRequestError) Error() string {
	return e.message
}

func (e *InvalidRequestError) Unwrap() error {
	return e.err
}

func ErrInvalidRequest(issuer string, msg string, err error) *InvalidRequestError {
	return &InvalidRequestError{message: fmt.Sprintf(`realm="%s",error="invalid_request",error_description="%s"`, issuer, msg), err: err}
}

type InvalidTokenError struct {
	message string
	err     error
}

func (e *InvalidTokenError) Error() string {
	return e.message
}

func (e *InvalidTokenError) Unwrap() error {
	return e.err
}

func ErrMissingAuthentication(err error) *InvalidTokenError {
	return &InvalidTokenError{message: "", err: err}
}

func ErrInvalidToken(issuer string, msg string, err error) *InvalidTokenError {
	return &InvalidTokenError{message: fmt.Sprintf(`realm="%s",error="invalid_token",error_description="%s"`, issuer, msg), err: err}
}

type InsufficientScopeError struct {
	message string
	err     error
}

func (e *InsufficientScopeError) Error() string {
	return e.message
}

func (e *InsufficientScopeError) Unwrap() error {
	return e.err
}
