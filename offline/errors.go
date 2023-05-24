package offline

import (
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

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

func interpretJWTError(issuer string, err error) error {

	if errors.Is(err, jwt.ErrInvalidIssuer()) {
		return ErrMissingAuthentication(err)
	}
	// 400
	if errors.Is(err, jwt.ErrInvalidAudience()) {
		return ErrInvalidRequest(issuer, "aud not satisfied", err)
	}
	if errors.Is(err, jwt.ErrInvalidJWT()) {
		return ErrInvalidRequest(issuer, "token not yet valid", err)
	}
	// 401
	if errors.Is(err, jwt.ErrInvalidIssuedAt()) {
		return ErrInvalidToken(issuer, "invalid iat", err)
	}
	if errors.Is(err, jwt.ErrTokenExpired()) {
		return ErrInvalidToken(issuer, "token expired", err)
	}
	if errors.Is(err, jwt.ErrTokenNotYetValid()) {
		return ErrInvalidToken(issuer, "token not yet valid", err)
	}

	return err
}
