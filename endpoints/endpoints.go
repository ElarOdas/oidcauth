package endpoints

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// ? Find a more concise way to write fetches (generic?)
func FetchIntrospection(issuer string) (*url.URL, error) {

	wellKnown := newWellKnownURL(issuer)

	rawIntrospection := struct {
		Introspection string `json:"introspection_endpoint"`
	}{}

	err := fetchJSON(wellKnown, &rawIntrospection)

	if err != nil {
		return nil, err
	}
	introspection := NewValidURL(rawIntrospection.Introspection)
	return introspection, nil
}

func FetchKeyEndpoint(issuer string) (*url.URL, error) {
	wellKnown := newWellKnownURL(issuer)

	rawKeys := struct {
		Keys string `json:"jwks_uri"`
	}{}

	err := fetchJSON(wellKnown, &rawKeys)

	if err != nil {
		return nil, err
	}
	keys := NewValidURL(rawKeys.Keys)
	return keys, nil
}

func fetchJSON[T any](url *url.URL, target *T) error {
	resp, err := http.Get(url.String())

	if err != nil {
		target = nil
		return err
	}
	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&target)

	if err != nil {
		target = nil
		return err
	}
	return nil
}

func newWellKnownURL(rawIssuer string) *url.URL {
	issuer := NewValidURL(rawIssuer)
	return issuer.JoinPath(".well-known", "openid-configuration")
}

func NewValidURL(rawURL string) *url.URL {
	newURL, err := url.Parse(rawURL)
	//not fixable at runtime --> Panic
	if err != nil || len(newURL.Host) == 0 {
		panic(fmt.Sprintf("Invalid URL: %s", rawURL))
	}
	return newURL
}
