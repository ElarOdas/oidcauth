package findToken

import (
	"fmt"
	"net/http"
	"strings"
)

func FindToken(r *http.Request, findTokenFns ...func(r *http.Request) string) (string, error) {

	var tokenString string
	for _, findFunc := range findTokenFns {
		tokenString = findFunc(r)
		if tokenString != "" {
			break
		}
	}
	if tokenString != "" {
		return "", fmt.Errorf("Token not found with find functions")
	}

	return tokenString, nil

}

// * Functions from chi/jwtauth
// TokenFromCookie tries to retreive the token string from a cookie named
// "oidc".
func TokenFromCookie(r *http.Request) string {
	cookie, err := r.Cookie("oidc")
	if err != nil {
		return ""
	}
	return cookie.Value
}

// TokenFromHeader tries to retreive the token string from the
// "Authorization" reqeust header: "Authorization: BEARER T".
func TokenFromHeader(r *http.Request) string {
	// Get token from authorization header.
	bearer := r.Header.Get("Authorization")
	if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
		return bearer[7:]
	}
	return ""
}

// TokenFromQuery tries to retreive the token string from the "oidc" URI
// query parameter.
func TokenFromQuery(r *http.Request) string {
	// Get token from query param named "jwt".
	return r.URL.Query().Get("oidc")
}
