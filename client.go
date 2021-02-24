package main

import (
	"context"
	"net"
	"net/http"
	"time"
)

func NewClient() *http.Client {
	return NewClientWithTimeout(30 * time.Second)
}

func NewClientWithTimeout(tout time.Duration) *http.Client {
	dialer := net.Dialer{
		Timeout:   tout,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath())
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &http.Client{
		Transport: transport,
	}
}
