package offline

import (
	"errors"
	"net/http"

	"github.com/ElarOdas/slices"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func VerifyOffline(off *Offline, r *http.Request) (jwt.Token, error) {
	token, err := jwt.ParseRequest(r, jwt.WithKeySet(off.KeySet))
	// Token is either missing (400), Key could not be found (401) or
	if err != nil {
		return nil, ErrMissingAuthentication(err)
	}

	err = jwt.Validate(token, jwt.WithIssuer(off.Issuer), jwt.WithAudience(off.Audience))
	if err != nil {
		return nil, getValidationError(off.Issuer, err)
	}

	return token, nil
}
func VerifyOfflineSlice(offs []*Offline, r *http.Request) (jwt.Token, error) {

	unverifiedIssuer, err := extractUnverifiedIssuer(r)

	// No iss in Token
	if err != nil {
		return nil, ErrMissingAuthentication(err)
	}

	off, err := findOffline(offs, unverifiedIssuer)
	// iss not in available
	if err != nil {
		return nil, ErrMissingAuthentication(err)
	}

	token, err := jwt.ParseRequest(r, jwt.WithKeySet(off.KeySet))
	if err != nil {
		return nil, ErrMissingAuthentication(err)
	}
	// ? Checking for Issuer unnecessary as we do it above
	err = jwt.Validate(token, jwt.WithAudience(off.Audience))
	if err != nil {
		return nil, getValidationError(off.Issuer, err)
	}

	return token, nil
}

func findOffline(offs []*Offline, issuer string) (*Offline, error) {
	//? Filter or Search might be better
	off, _ := slices.UnorderedReduceSlice(offs, func(off *Offline, basis *Offline) (*Offline, error) {
		if off.Issuer != issuer {
			return basis, nil
		}
		return off, nil
	}, nil)
	if off == nil {
		return nil, jwt.ErrInvalidIssuer()
	}
	return off, nil
}

func extractUnverifiedIssuer(r *http.Request) (string, error) {
	token, err := jwt.ParseRequest(r, jwt.WithVerify(false))
	if err != nil {
		return "", err
	}
	if len(token.Issuer()) == 0 {
		return "", jwt.ErrInvalidIssuer()
	}
	return token.Issuer(), nil
}

func getValidationError(issuer string, err error) error {

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
