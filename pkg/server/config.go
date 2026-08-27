package server

import (
	"net/http"
	"time"

	"sigsum.org/sigsum-go/pkg/types"
)

const (
	defaultTimeout = 30 * time.Second
)

type Config struct {
	Prefix           string
	Timeout          time.Duration
	HandlerDecorator func(http.Handler, types.Endpoint) http.Handler
}

func (c *Config) withDefaults() Config {
	config := *c
	if config.Timeout == 0 {
		config.Timeout = defaultTimeout
	}
	if config.HandlerDecorator == nil {
		config.HandlerDecorator = func(handler http.Handler, _ types.Endpoint) http.Handler {
			return handler
		}
	}
	return config
}
