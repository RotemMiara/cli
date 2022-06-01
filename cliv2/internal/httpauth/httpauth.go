package httpauth

import (
	"net/http"

	"github.com/dpotapov/go-spnego"
)

const (
	AuthorizationKey      string = "Authorization"
	ProxyAuthorizationKey string = "Proxy-Authorization"
)

type AuthenticationMechanism int

const (
	NoAuth    AuthenticationMechanism = iota
	Mock      AuthenticationMechanism = iota
	Negotiate AuthenticationMechanism = iota
)

type AuthenticationHandler struct {
	Mechanism AuthenticationMechanism
}

func (a *AuthenticationHandler) GetProxyAuthenticationValue(req *http.Request) (responseToken string, err error) {

	var authorizeValue string

	if a.Mechanism == Negotiate {
		// supporting Negotiate mechanism (SPNEGO)
		var provider spnego.Provider = spnego.New()
		cannonicalize := false

		if err := provider.SetSPNEGOHeader(req, cannonicalize); err != nil {
			return "", err
		}

	} else if a.Mechanism == Mock {
		req.Header.Set(AuthorizationKey, "Mock YWxhZGRpbjpvcGVuc2VzYW1l")
	}

	// ugly work around the fact that go-spnego only adds an "Authorize" Header and not "Proxy-Authorize"
	authorizeValue = req.Header.Get(AuthorizationKey)
	req.Header.Del(AuthorizationKey)

	return authorizeValue, nil
}

func (a *AuthenticationHandler) AddProxyAuthenticationHeader(req *http.Request) (err error) {

	proxyAuthorizeValue, err := a.GetProxyAuthenticationValue(req)
	req.Header.Add(ProxyAuthorizationKey, proxyAuthorizeValue)

	return err
}
