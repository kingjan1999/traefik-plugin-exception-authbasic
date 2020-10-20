package traefik_plugin_exception_basicauth_test

import (
	"context"
	traefik_plugin_exception_basicauth "github.com/kingjan1999/traefik-plugin-exception-basicauth"
	"net/http"
	"net/http/httptest"
	"testing"
)

const Username = "user"
const Password = "password"
const AuthHeader = "Basic dXNlcjpwYXNzd29yZA=="

func TestExceptBasicAuth_AllowIp(t *testing.T) {
	cfg := traefik_plugin_exception_basicauth.CreateConfig()
	cfg.AllowIpList = []string{"127.0.0.1"}
	cfg.User = Username
	cfg.Password = Password
	assertAuthHeader(t, cfg, "127.0.0.1:1234", AuthHeader)
}

func TestExceptBasicAuth_DenyIp(t *testing.T) {
	cfg := traefik_plugin_exception_basicauth.CreateConfig()
	cfg.AllowIpList = []string{"127.0.0.1"}
	cfg.User = Username
	cfg.Password = Password
	assertAuthHeader(t, cfg, "127.0.0.2:1234", "")
}

func TestExceptBasicAuth_DenyUser(t *testing.T) {
	cfg := traefik_plugin_exception_basicauth.CreateConfig()
	cfg.AllowIpList = []string{"127.0.0.1"}
	cfg.User = Username
	cfg.Password = Password
	cfg.PreventUser = true

	handler, err, recorder, req := createReqAndRecorder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "127.0.0.2"
	req.Header.Set("Authorization", AuthHeader)

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("Invalid status code: %d", recorder.Code)
	}
}

func TestExceptBasicAuth_AllowUser(t *testing.T) {
	cfg := traefik_plugin_exception_basicauth.CreateConfig()
	cfg.AllowIpList = []string{"127.0.0.1"}
	cfg.User = Username
	cfg.Password = Password

	handler, err, recorder, req := createReqAndRecorder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "127.0.0.2"
	req.Header.Set("Authorization", AuthHeader)

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Invalid status code: %d", recorder.Code)
	}

	assertHeader(t, req, "Authorization", AuthHeader)
}

func createReqAndRecorder(cfg *traefik_plugin_exception_basicauth.Config) (http.Handler, error, *httptest.ResponseRecorder, *http.Request) {
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	handler, err := traefik_plugin_exception_basicauth.New(ctx, next, cfg, "except-basic-auth-plugin")
	if err != nil {
		return nil, err, nil, nil
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	return handler, err, recorder, req
}

func assertAuthHeader(t *testing.T, cfg *traefik_plugin_exception_basicauth.Config, remoteIp, expectedHeaderValue string) {
	t.Helper()

	handler, err, recorder, req := createReqAndRecorder(cfg)
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
