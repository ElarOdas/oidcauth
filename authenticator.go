package oidcauth

import (
	"errors"
	"fmt"

	"net/http"

	"github.com/ElarOdas/oidcauth/offline"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func Authenticator(logf func(v ...any)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		hfn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, _, err := FromContext(r.Context())

			//TODO Error Codes according to https://www.rfc-editor.org/rfc/rfc6750#section-3.1

			// Default

			if err != nil {
				logf("failed token auth:", errors.Unwrap(err))
				var invalidRequest *offline.InvalidRequestError
				var invalidToken *offline.InvalidTokenError
				//  400 invalid request
				if errors.As(err, &invalidRequest) {
					w.Header().Add("WWW-Authenticate", fmt.Sprintf("Bearer %s", err.Error()))
					http.Error(w, "", http.StatusBadRequest)

					return
				}
				// 401 invalid token
				if errors.As(err, &invalidToken) {
					w.Header().Add("WWW-Authenticate", fmt.Sprintf("Bearer %s", err.Error()))
					http.Error(w, "", http.StatusUnauthorized)
					return
				}
				// if errors.As(err, &insufficientScope) {
				// 	w.Header().Add("WWW-Authenticate", fmt.Sprintf("Bearer %s", err.Error()))
				// 	http.Error(w, "", http.StatusForbidden)
				// 	log.Error(errors.Unwrap(err))
				// 	return
				// }

				// Default to 400
				http.Error(w, "", http.StatusBadRequest)
				return

			}

			if token == nil || jwt.Validate(token) != nil {
				http.Error(w, "", http.StatusBadRequest)
				return
			}

			// Token is authenticated, pass it through
			next.ServeHTTP(w, r)

		})
		return hfn
	}

}
