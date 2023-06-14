package offline

import (
	"net/http"

	"github.com/PVolpert/oidcauth/findToken"
	"github.com/PVolpert/slices"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func VerifyOffline(off *Offline, r *http.Request) (jwt.Token, error) {
	// extract the keys from either Header,Cookie or Query
	tokenString, err := findToken.FindToken(r, findToken.TokenFromHeader, findToken.TokenFromCookie, findToken.TokenFromQuery)
	if err != nil {
		return nil, ErrMissingAuthentication(err)
	}
	return parseAndValidate(off, tokenString)
}
func VerifyOfflineSlice(offs []*Offline, r *http.Request) (jwt.Token, error) {
	// TODO
	// extract the keys from either Header,Cookie or Query
	tokenString, err := findToken.FindToken(r, findToken.TokenFromHeader, findToken.TokenFromCookie, findToken.TokenFromQuery)
	if err != nil {
		return nil, ErrMissingAuthentication(err)
	}
	off, err := findOffline(offs, tokenString)
	// iss not in available
	if err != nil {
		return nil, ErrMissingAuthentication(err)
	}
	return parseAndValidate(off, tokenString)
}

func parseAndValidate(off *Offline, tokenString string) (jwt.Token, error) {
	// Verify sign of token
	token, err := jwt.Parse([]byte(tokenString), jwt.WithKeySet(off.KeySet))
	if err != nil {
		return nil, ErrMissingAuthentication(err)
	}
	// Verify content of token
	issuer := off.Issuer
	if len(off.OutsideIssuer) != 0 {
		issuer = off.OutsideIssuer
	}

	err = jwt.Validate(token, jwt.WithIssuer(issuer), jwt.WithAudience(off.Audience))
	if err != nil {
		return nil, interpretJWTError(issuer, err)
	}

	return token, nil
}

func findOffline(offs []*Offline, tokenString string) (*Offline, error) {
	// Get issuer from token
	unverifiedIssuer, err := extractUnverifiedIssuer(tokenString)
	// No iss in Token
	if err != nil {
		return nil, ErrMissingAuthentication(err)
	}
	// Search for the correct issuer
	off, _ := slices.UnorderedReduceSlice(offs, func(off *Offline, basis *Offline) (*Offline, error) {
		if off.Issuer != unverifiedIssuer {
			return basis, nil
		}
		return off, nil
	}, nil)
	if off == nil {
		return nil, jwt.ErrInvalidIssuer()
	}
	return off, nil
}

func extractUnverifiedIssuer(tokenString string) (string, error) {
	token, err := jwt.Parse([]byte(tokenString), jwt.WithVerify(false))
	if err != nil {
		return "", err
	}
	if len(token.Issuer()) == 0 {
		return "", jwt.ErrInvalidIssuer()
	}
	return token.Issuer(), nil
}
