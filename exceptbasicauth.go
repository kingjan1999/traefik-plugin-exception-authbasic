package traefik_plugin_exception_basicauth

import (
	"context"
	"net"
	"net/http"
)

type Config struct {
	AllowIpList []string `json:"allowIpList,omitempty"`
	User        string   `json:"user"`
	Password    string   `json:"password"`
	PreventUser bool     `json:"preventUser"`
}

func CreateConfig() *Config {
	return &Config{}
}

type ExceptBasicAuth struct {
	next   http.Handler
	name   string
	config *Config
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &ExceptBasicAuth{
		name:   name,
		next:   next,
		config: config,
	}, nil
}

func (e *ExceptBasicAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err == nil && e.IsIpAllowed(ip) {
		req.SetBasicAuth(e.config.User, e.config.Password)
		// req.Header.Set("Authorization", fmt.Sprintf("Basic %s", basicAuth(e.config.User, e.config.Password)))
	} else if e.config.PreventUser && req.Header.Get("Authorization") != "" {
		user, _, ok := req.BasicAuth()
		if ok && user == e.config.User {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	e.next.ServeHTTP(rw, req)
}

func (e *ExceptBasicAuth) IsIpAllowed(ip string) bool {
	for _, allowedIp := range e.config.AllowIpList {
		if allowedIp == ip {
			return true
		}
	}

	return false
}
