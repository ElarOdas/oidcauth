package online

import (
	"net/url"
	"strings"

	"github.com/ElarOdas/oidcauth/endpoints"
)

type Online struct {
	Issuer        string
	Introspection *url.URL
	ClientId      string
	ClientSecret  string
	TargetId      string
}

func New(issuer string, clientId string, clientSecret string, targetId string) (*Online, error) {
	introspection, err := endpoints.FetchIntrospection(issuer)

	if err != nil {
		return nil, err
	}

	on := &Online{
		Issuer:        strings.TrimRight(issuer, "/"),
		Introspection: introspection,
		ClientId:      clientId,
		ClientSecret:  clientSecret,
		TargetId:      targetId,
	}
	return on, nil
}
