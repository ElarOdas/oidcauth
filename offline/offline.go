package offline

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ElarOdas/oidcauth/endpoints"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type Offline struct {
	Issuer      string
	Audience    string
	KeyEndpoint *url.URL
	KeySet      jwk.Set
}

func New(issuer string, audience string, refreshPeriod time.Duration) (*Offline, error) {
	//Query the well OIDC endpoint
	keyEndpoint, err := endpoints.FetchKeyEndpoint(issuer)

	if err != nil {
		return nil, err
	}
	off := &Offline{
		Issuer:      strings.TrimRight(issuer, "/"),
		Audience:    audience,
		KeyEndpoint: keyEndpoint,
	}
	off.newCachedSet(refreshPeriod)
	return off, nil
}

func (off *Offline) newCachedSet(refreshPeriod time.Duration) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := jwk.NewCache(ctx)
	// ? Give user the option for interval length
	c.Register(off.KeyEndpoint.String(), jwk.WithMinRefreshInterval(refreshPeriod))
	_, err := c.Refresh(ctx, off.KeyEndpoint.String())
	if err != nil {
		fmt.Printf("Failed to refresh")
		return
	}
	cached := jwk.NewCachedSet(c, off.KeyEndpoint.String())

	off.KeySet = cached
}
