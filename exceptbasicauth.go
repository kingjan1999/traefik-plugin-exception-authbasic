package traefik_plugin_exception_basicauth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
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
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s", basicAuth(e.config.User, e.config.Password)))
	} else if e.config.PreventUser && req.Header.Get("Authorization") != "" {
		user, _, err := parseBasicAuth(req.Header.Get("Authorization"))
		if err == nil && user == e.config.User {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		} else {
			log.Printf("%v for %s", err, user)
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

func basicAuth(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}

func parseBasicAuth(headerValue string) (string, string, error) {
	if !strings.HasPrefix(headerValue, "Basic") {
		return "", "", errors.New("invalid auth header")
	}

	decoded, err := base64.StdEncoding.DecodeString(headerValue[6:])
	if err != nil {
		return "", "", err
	}

	decodedString := string(decoded)
	values := strings.Split(decodedString, ":")
	if len(values) != 2 {
		return "", "", errors.New("invalid auth header")
	}
	return values[0], values[1], nil
}
