package oidcauth

import (
	"context"
	"errors"
	"net/http"

	"github.com/ElarOdas/oidcauth/offline"
	// "github.com/ElarOdas/oidcauth/online"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var (
	TokenCtxKey = &contextKey{"Token"}
	ErrorCtxKey = &contextKey{"Error"}
)

type verificationProp interface {
	*offline.Offline | []*offline.Offline // | *online.Online | []*online.Online
}

// go-chi middleware
func Verifier[prop verificationProp](vp prop) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		hfn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			// actual verification based on given prop
			token, err := verifyToken(vp, r)

			ctx = NewContext(ctx, token, err)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(hfn)
	}
}

func verifyToken[prop verificationProp](vp prop, r *http.Request) (jwt.Token, error) {
	// any needed for type switch
	switch typedvp := any(vp).(type) {
	case *offline.Offline:
		return offline.VerifyOffline(typedvp, r)
	case []*offline.Offline:
		return offline.VerifyOfflineSlice(typedvp, r)
		// case *online.Online:
		// 	return online.VerifyOnline(typedvp, r)
		// case []*online.Online:
		// 	return online.VerifyOnlineSlice(typedvp, r)
	}
	//! Is never reached but needed because of any() cast
	err := errors.New("this value should not be reachable :O")
	panic(err)
}

// ! Below this are direct copies of go-chi jwtauth functions
//  https://github.com/go-chi/jwtauth/blob/master/jwtauth.go

func FromContext(ctx context.Context) (jwt.Token, map[string]interface{}, error) {
	token, _ := ctx.Value(TokenCtxKey).(jwt.Token)

	var err error
	var claims map[string]interface{}

	if token != nil {
		claims, err = token.AsMap(context.Background())
		if err != nil {
			return token, nil, err
		}
	} else {
		claims = map[string]interface{}{}
	}

	err, _ = ctx.Value(ErrorCtxKey).(error)

	return token, claims, err
}

func NewContext(ctx context.Context, t jwt.Token, err error) context.Context {
	ctx = context.WithValue(ctx, TokenCtxKey, t)
	ctx = context.WithValue(ctx, ErrorCtxKey, err)
	return ctx
}

// contextKey is a value for use with context.WithValue. It's used as
// a pointer so it fits in an interface{} without allocation. This technique
// for defining context keys was copied from Go 1.7's new use of context in net/http.
type contextKey struct {
	name string
}

func (k *contextKey) String() string {
	return "jwtauth context value " + k.name
}
