package server

import (
	"time"
)

const (
	defaultTimeout = 30 * time.Second
)

type Metrics interface {
	OnRequest(pattern string)
	OnResponse(pattern string, status int, latency time.Duration)
}

type noMetrics struct{}

func (_ noMetrics) OnRequest(_ string)                          {}
func (_ noMetrics) OnResponse(_ string, _ int, _ time.Duration) {}

type Config struct {
	Prefix  string
	Timeout time.Duration
	Metrics Metrics
}

func (c *Config) withDefaults() Config {
	config := *c
	if config.Timeout == 0 {
		config.Timeout = defaultTimeout
	}
	if config.Metrics == nil {
		config.Metrics = noMetrics{}
	}
	return config
}
