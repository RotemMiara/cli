package httpauth_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/snyk/cli/cliv2/internal/httpauth"
	"github.com/stretchr/testify/assert"
)

func getTestRequest() http.Request {
	request := http.Request{}
	request.URL, _ = url.Parse("https://snyk.io")
	request.Header = map[string][]string{
		"Accept-Encoding": {"gzip, deflate"},
		"Accept-Language": {"en-us"},
		"Foo":             {"Bar", "two"},
	}
	return request
}

func Test_DisableAuthentication(t *testing.T) {

	request := getTestRequest()

	authHandler := httpauth.AuthenticationHandler{
		Mechanism: httpauth.NoAuth,
	}

	err := authHandler.AddProxyAuthenticationHeader(&request)
	assert.Nil(t, err)

	proxyAuthValue := request.Header.Get(httpauth.ProxyAuthorizationKey)
	assert.Empty(t, proxyAuthValue)

}

func Test_EnabledAuthentication_Mock(t *testing.T) {

	request := getTestRequest()

	authHandler := httpauth.AuthenticationHandler{
		Mechanism: httpauth.Mock,
	}

	err := authHandler.AddProxyAuthenticationHeader(&request)
	assert.Nil(t, err)

	proxyAuthValue := request.Header.Get(httpauth.ProxyAuthorizationKey)
	assert.Contains(t, proxyAuthValue, "Mock")

	AuthValue := request.Header.Get(httpauth.AuthorizationKey)
	assert.Empty(t, AuthValue)

}
