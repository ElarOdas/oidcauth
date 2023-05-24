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

// Create a new offline struct by querying the well-known endpoint of the issuer
func New(issuer string, audience string, refreshPeriod time.Duration) (*Offline, error) {
	//Query the well-known OIDC endpoint for key endpoint
	keyEndpoint, err := endpoints.FetchKeyEndpoint(issuer)
	if err != nil {
		return nil, err
	}
	off := &Offline{
		Issuer:      strings.TrimRight(issuer, "/"),
		Audience:    audience,
		KeyEndpoint: keyEndpoint,
	}
	//Query the key endpoint for keys in use by issuer
	off.newCachedSet(refreshPeriod)
	return off, nil
}

// Create a jwt keyset that renews itself every refreshPeriod
// For more details see the jwx documentation
func (off *Offline) newCachedSet(refreshPeriod time.Duration) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := jwk.NewCache(ctx)
	c.Register(off.KeyEndpoint.String(), jwk.WithMinRefreshInterval(refreshPeriod))
	_, err := c.Refresh(ctx, off.KeyEndpoint.String())
	if err != nil {
		fmt.Printf("Failed to refresh")
		return
	}
	cached := jwk.NewCachedSet(c, off.KeyEndpoint.String())

	off.KeySet = cached
}
