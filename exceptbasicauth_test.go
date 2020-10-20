package traefik_plugin_exception_basicauth_test

import (
	"context"
	traefik_plugin_exception_basicauth "github.com/kingjan1999/traefik-plugin-exception-basicauth"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExceptBasicAuth_AllowIp(t *testing.T) {
	cfg := traefik_plugin_exception_basicauth.CreateConfig()
	cfg.AllowIpList = []string{"127.0.0.1"}
	cfg.User = "user"
	cfg.Password = "password"
	assertAuthHeader(t, cfg, "127.0.0.1:1234", "Basic dXNlcjpwYXNzd29yZA==")
}

func TestExceptBasicAuth_DenyIp(t *testing.T) {
	cfg := traefik_plugin_exception_basicauth.CreateConfig()
	cfg.AllowIpList = []string{"127.0.0.1"}
	cfg.User = "user"
	cfg.Password = "password"
	assertAuthHeader(t, cfg, "127.0.0.2:1234", "")
}

func assertAuthHeader(t *testing.T, cfg *traefik_plugin_exception_basicauth.Config, remoteIp, expectedHeaderValue string) {
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := traefik_plugin_exception_basicauth.New(ctx, next, cfg, "except-basic-auth-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = remoteIp

	handler.ServeHTTP(recorder, req)

	assertHeader(t, req, "Authorization", expectedHeaderValue)
}

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	if req.Header.Get(key) != expected {
		t.Errorf("invalid header value: %s", req.Header.Get(key))
	}
}
