package traefik_plugin_exception_basicauth

import (
	"context"
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
	next          http.Handler
	name          string
	config        *Config
	allowedIps    []*net.IP
	allowedIpNets []*net.IPNet
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	var allowedIps []*net.IP
	var allowedIpNets []*net.IPNet

	for _, allowedIp := range config.AllowIpList {
		ip, ipNet, err := parseIp(allowedIp)

		if err != nil {
			log.Printf("Failed to parse ip %s: %v", allowedIp, err)
		} else if ip != nil {
			allowedIps = append(allowedIps, ip)
		} else if ipNet != nil {
			allowedIpNets = append(allowedIpNets, ipNet)
		}
	}

	return &ExceptBasicAuth{
		name:   name,
		next:   next,
		config: config,
		allowedIpNets: allowedIpNets,
		allowedIps: allowedIps,
	}, nil
}

func (e *ExceptBasicAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err == nil && e.IsIpAllowed(ip) {
		req.SetBasicAuth(e.config.User, e.config.Password)
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
	parsedIp := net.ParseIP(ip);

	if parsedIp == nil {
		log.Printf("Failed to parse ip: %s", ip);
		return false
	}

	for _, allowedIp := range e.allowedIps {
		if allowedIp.Equal(parsedIp) {
			return true
		}
	}

	for _, allowedIpnet := range e.allowedIpNets {
		if allowedIpnet.Contains(parsedIp) {
			return true
		}
	}

	return false
}

func parseIp(allowedIp string) (*net.IP, *net.IPNet, error) {
	if strings.Contains(allowedIp, "/") {
		_, ipNet, err := net.ParseCIDR(allowedIp)
		if err != nil {
			return nil, nil, fmt.Errorf("Unable to parse %s as cidr, skipping", allowedIp)
		}
		return nil, ipNet, err
	} else {
		parsedIp := net.ParseIP(allowedIp)
		if parsedIp == nil {
			return nil, nil, fmt.Errorf("Unable to parse ip %s, skipping", allowedIp)
		} else {
			return &parsedIp, nil, nil
		}
	}
}
