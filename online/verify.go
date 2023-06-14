package online

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"net/http"
	"net/url"

	"github.com/PVolpert/slices"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func VerifyOnline(on *Online, r *http.Request) (jwt.Token, error) {
	token, err := jwt.ParseRequest(r, jwt.WithVerify(false))

	//Failed to parse form (400)
	if err != nil {
		return nil, err
	}
	compactToken := compactTokenFromHeader(r)

	isActive, err := isTokenActive(on, compactToken)
	//Introspection endpoint can not be reached (400)

	if err != nil {
		return nil, err
	}

	// Token is invalid (401)
	if !isActive {
		return nil, errors.New("token invalid")
	}

	return token, nil
}
func VerifyOnlineSlice(ons []*Online, r *http.Request) (jwt.Token, error) {
	token, err := extractUnverifiedToken(r)
	//Failed to parse form (400)
	if err != nil {
		return nil, err
	}
	//Token contains no issuer (400)
	if len(token.Issuer()) == 0 {
		return nil, errors.New("missing issuer")
	}
	on, err := findOnline(ons, token.Issuer())
	//Token comes from an unknown issuer (401)
	if err != nil {
		return nil, err
	}

	compactToken := compactTokenFromHeader(r)
	isActive, err := isTokenActive(on, compactToken)
	//Introspection endpoint can not be reached (400)
	if err != nil {
		return nil, err
	}

	if !isActive {
		return nil, errors.New("Unauthorized")
	}

	return token, nil
}

func extractUnverifiedToken(r *http.Request) (jwt.Token, error) {
	token, err := jwt.ParseRequest(r, jwt.WithVerify(false))
	if err != nil {
		return nil, err
	}
	return token, nil
}

func isTokenActive(on *Online, compactToken string) (bool, error) {

	hc := http.Client{}

	req, err := generateIntrospectionRequest(on, compactToken)
	if err != nil {
		return false, err
	}
	fmt.Println(req.PostForm.Encode())

	resp, err := hc.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// reylBytes, _ := httputil.DumpResponse(resp, true)
	// fmt.Println(string(reylBytes))

	isActive, err := parseIntrospectionResponse(resp)

	if err != nil {
		return false, err
	}

	return isActive, err
}

func generateIntrospectionRequest(on *Online, compactToken string) (*http.Request, error) {
	form := url.Values{
		"token_type_hint": {"requesting_party_token"},
		"token":           {compactToken},
		"client_id":       {on.TargetId},
	}
	req, err := http.NewRequest(http.MethodPost, on.Introspection.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(on.ClientId, on.ClientSecret)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()

	return req, nil
}

func parseIntrospectionResponse(resp *http.Response) (bool, error) {
	if resp.StatusCode != http.StatusOK {
		return false, errors.New("Denied because of" + resp.Status)
	}

	active := struct {
		Active bool `json:"active"`
	}{}

	err := json.NewDecoder(resp.Body).Decode(&active)

	if err != nil {
		return false, err
	}
	return active.Active, nil
}

func findOnline(ons []*Online, issuer string) (*Online, error) {
	//? Filter or Search might be better
	on, _ := slices.UnorderedReduceSlice(ons, func(on *Online, basis *Online) (*Online, error) {
		if on.Issuer != issuer {
			return basis, nil
		}
		return on, nil
	}, nil)
	if on == nil {
		return nil, errors.New("no matching issuer found")
	}
	return on, nil
}

// From https://github.com/go-chi/jwtauth/blob/master/jwtauth.go
//
//	TokenFromHeader tries to retreive the token string from the
//
// "Authorization" reqeust header: "Authorization: BEARER T".
func compactTokenFromHeader(r *http.Request) string {
	// Get token from authorization header.
	bearer := r.Header.Get("Authorization")
	if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
		return bearer[7:]
	}
	return ""
}
